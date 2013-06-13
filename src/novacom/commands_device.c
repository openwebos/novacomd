/* @@@LICENSE
*
*      Copyright (c) 2008-2013 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#if DEVICE
#include <pwd.h>
#include "device/auth.h"
#endif

#include <debug.h>
#include <platform.h>
#include <novacom.h>

#include "novacom_p.h"
#include "mux.h"
#include "packet.h"
#include "buf_queue.h"

#define LOCAL_TRACE    0
#define TRACE_COMMANDS 0

// === IO stuff here ===

#define PIPE_READ 0
#define PIPE_WRITE 1

#define QUEUE_MAX 65536
#define RWSIZE 16384

struct channel_notify_cb_args {
	int stdoutpipe;
	int stderrpipe;
};


/* writer thread control structure */
typedef struct fd_writer_args {
	device_handle_t device_handle;
	platform_event_t *done;			/* termination event */
	buf_queue_t *in_queue;			/* input stream queue (from packet thread) */ 
	int channel;
	int fd;							/* fd stream */
	int rcode;						/* return code: error if any */
} fd_writer_args_t;

/* reader thread control structure */
typedef struct fd_reader_args {
	device_handle_t device_handle;
	platform_event_t *done;			/* termnination event */
	int channel;
	int stream_id;					/* stream id */
	int fd;							/* fd stream */
	int closepipe;					/* fd pipe to close stream */
	int rcode;						/* return code: error if any */
} fd_reader_args_t;

/* start_fds_thread control structure */
typedef struct start_fds_args {
	int stdinfd;					/* stdin */
	int stdoutfd;					/* stdout */
	int stderrfd;					/* stderr */
	device_handle_t device_handle;	/* device handle */
	int channel;					/* channel */
	pid_t child;					/* spawned child pid_tq */
	int stdout_lead;				/* close channel if stdout gets closed */ 
} start_fds_args_t;

/* channel close callback control structure */
typedef struct channel_closefd_callback_args {
	int closepipe;					/* pipe id */
	int channel;					/* channel */
} channel_closefd_callback_args_t;

struct callback_to_bufq_args {
	buf_queue_t *queue;
};

/* callback from mux layer */
static int callback_to_bufq(device_handle_t device_handle, uint32_t chan, int err, const void *buf, size_t len, void *cookie)
{
	struct callback_to_bufq_args *args = (struct callback_to_bufq_args *)cookie;
	
	if (err < 0) {
		LTRACEF("novacom channel %d of device %p closed, closing the in_queue\n", chan, device_handle);
		bufq_close(args->queue);
		platform_free(cookie);
		return 0;
	}

	if (bufq_len(args->queue) > QUEUE_MAX) {
		return -1;
	} else {
		bufq_append_data(args->queue, buf, len);
	}
	return 0;
}

/* writer worker thread */
static void *writer_worker_thread(void *arg)
{
	device_pthread_setaffinity();

	struct fd_writer_args *args = (struct fd_writer_args *)arg;
	int rc, towrite, writepos;
	char *buf = NULL;
	size_t total_data = 0;

	buf = platform_calloc(RWSIZE);
	if(!buf)
		goto exit;

	while (true) {
		// sleep on reading the first byte
		rc = bufq_read_sleepempty(args->in_queue, buf, RWSIZE);
		if (rc > 0) {
			towrite = rc;
			writepos = 0;
			while(towrite > 0) {
				rc = write(args->fd, buf + writepos, towrite);
				/* 0, -1 considered to be error */
				if (rc < 1 ) {
					char str[64];
					/* retry or interrupted by signal? */
					if( (errno == EINTR || errno == EAGAIN) ) {
						continue;
					}
					str[0] = 0;	/* clear string */
					snprintf(str, sizeof(str), "%s\n", strerror(errno));
					if( send_packet_err(args->device_handle, args->channel, str, strlen(str)+1) < 0) {
						TRACEL(LOG_ERROR, "Unable to send error message:(%s)\n", str);
					} else {
						LTRACEF("Write file error(%s)", str);
					}
					args->rcode = errno; /* save return code */
					goto exit;
				}
				towrite -= rc;
				writepos += rc;
				total_data += rc;
			}
		} else {
			LTRACEF("Unable to read data from queue\n");
			goto exit;
		}
	}
exit:
	if(send_packet_eof(args->device_handle, args->channel, STDIN_FILENO) < 0) {
		LTRACEF("unable to send STDIN EOF\n");
	}
	LTRACEF("closing fd; sent %u bytes\n", total_data);
	platform_free(buf);
	close(args->fd);
	platform_event_signal(args->done);
	LTRACEF("exit\n");
	return NULL;
}


/*
 *  reader worker thread
 *  we could probably combine reader threads in future
 */
static void *reader_worker_thread(void *arg)
{
	device_pthread_setaffinity();

	fd_reader_args_t *args = (fd_reader_args_t *)arg;
	int rc;

	char *buf = NULL;
	fd_set readfds;
	FILE *fp = NULL;

	buf = platform_calloc(RWSIZE);
	if(!buf)
		goto exit;

	/* check */
	if(!arg)
		goto exit;

	/* open stream only for stdout && regular file */
	if(args->stream_id == STDOUT_FILENO) {
		struct stat st;

		memset(&st, 0, sizeof(st));
		rc = fstat(args->fd, &st);

		/* regular file? */
		if( (rc != -1) && (S_ISREG(st.st_mode)) ) {
			LTRACEF("output stream\n");
			fp = fdopen(args->fd, "rb");
		}
	}

	/* read cycle */
	while (true) {

		FD_ZERO(&readfds);
		FD_SET(args->fd, &readfds);
		FD_SET(args->closepipe, &readfds);

		rc = select(MAX(args->fd, args->closepipe) + 1, &readfds, NULL, NULL, NULL);
		if ((-1 == rc) && ((EAGAIN == errno) || (EINTR == errno))) {
			continue;
		}

		if (FD_ISSET(args->closepipe, &readfds)) {
			rc = read(args->closepipe, buf, RWSIZE); // drain it, ignore return value
			LTRACEF("closepipe message, channel(%d),closepipe fd(%d), read(%d), buf[0]=0x%02x, errno(%d)::exit\n",
						args->channel, args->closepipe, rc, buf[0], errno);
			goto exit;
		}

		if (FD_ISSET(args->fd, &readfds)) {
			/* get data from fd or stream */
			if(fp) {
				rc = fread(buf, 1, RWSIZE, fp);
			} else {
				rc = read(args->fd, buf, RWSIZE);
			}

			///LTRACEF("read(%d), stream_id(%d)\n", rc, args->stream_id);

			if (rc > 0) {
				if(args->stream_id == STDOUT_FILENO) {
					rc = send_packet_data(args->device_handle, args->channel, buf, rc);
				} else {
					rc = send_packet_err(args->device_handle, args->channel, buf, rc);
				}
				if(rc < 0) {
					LTRACEF("exit:send_packet rc(%d), channel(%d), stream_id(%d), errno(%d)\n",
								rc, args->channel, args->stream_id, errno);
					goto exit;
				}
			} else {
				LTRACEF("read(%d), channel(%d), stream_id(%d), errno(%d)::exit\n",
							rc, args->channel, args->stream_id, errno);
				/* rc = 0 is EOF, skip it */
				if(rc != 0) {
					args->rcode = errno;
				}
				goto eof;
			}

			/* stream? check for stream eof */
			if(fp) {
				if( feof(fp) ) {
					LTRACEF("EOF detected\n");
					goto eof;
				}
			}
		}
	}

eof:
	send_packet_eof(args->device_handle, args->channel, args->stream_id);
exit:
	platform_free(buf);
	if(arg) {
		LTRACEF("exit: channel(%d), stream(%d), fd(%d)\n", args->channel, args->stream_id, args->fd);
		if(fp) {
			fclose(fp);
		} else {
			close(args->fd);
		}
		platform_event_signal(args->done);
	}
	return NULL;
}

static void channel_closefd_callback(void *cookie)
{
	channel_closefd_callback_args_t *args = (channel_closefd_callback_args_t *)cookie;
	char c = 0x04; // chosen by fair dice roll, guaranteed to be random
	LTRACEF("channel closed: closepipe fd(%d), channel(%d)\n", args->closepipe, args->channel);
	int rc = write(args->closepipe, &c, 1);
	if(rc < 0) {
		rc = write(args->closepipe, &c, 1);
	}
	platform_free(args);
}


static void *start_fds_thread(void *arg)
{
	device_pthread_setaffinity();

	start_fds_args_t *args = (start_fds_args_t *)arg;
	fd_reader_args_t *stdout_args = NULL;						/* reader::stdout */
	channel_closefd_callback_args_t *stdoutccc_args = NULL;
	fd_reader_args_t *stderr_args = NULL;						/* reader::stderr */
	channel_closefd_callback_args_t *stderrccc_args = NULL;
	fd_writer_args_t *stdin_args = NULL;						/* writer::stdin */
	int stdoutpipe[2] = {-1,-1};
	int stderrpipe[2] = {-1,-1};
	int rc = 0;
	int returncode = 0; /* no errors by default */
	platform_event_t stdout_event;
	platform_event_t stderr_event;
	platform_event_t stdin_event;
	platform_event_t packet_event;
	// input_queue->packet_thread->output_queue->writer_worker_thread
	buf_queue_t *input_queue = NULL;							/* input queue/stream */
	buf_queue_t *out_queue = NULL;								/* output queue/stream */

	LTRACEF("stdoutfd %d, stderrfd %d, stdinfd %d\n", args->stdoutfd, args->stderrfd, args->stdinfd);

	/* send back a success message before starting threads */
	rc = novacom_write_channel_sync(args->device_handle, args->channel, NOVACOMDMSG_REPLY_OK, strlen(NOVACOMDMSG_REPLY_OK));
	if(rc < 0) {
		TRACEF("unable to send reply, abort command: channel(%d)\n", args->channel);
		goto error;
	}

	/* events, input stream queue */
	platform_event_create(&stdout_event);
	platform_event_create(&stderr_event);
	platform_event_create(&stdin_event);
	platform_event_create(&packet_event);
	input_queue = bufq_create();

	/* callback_to_bufq */
	struct callback_to_bufq_args *cbq_args = platform_alloc(sizeof(struct callback_to_bufq_args));
	platform_assert(cbq_args);
	cbq_args->queue = input_queue;
	platform_assert(cbq_args->queue);
	novacom_set_read_callback(args->device_handle, args->channel, callback_to_bufq, (void *)cbq_args);

	/* stdout */
	if( (args->stdoutfd != -1) && (pipe(stdoutpipe) == 0) ){
		stdoutccc_args = platform_calloc(sizeof(channel_closefd_callback_args_t));
		platform_assert(stdoutccc_args);
		stdout_args = platform_calloc(sizeof(fd_reader_args_t));
		platform_assert(stdout_args);

		LTRACEF("STDOUTPIPE: open %d/%d\n", stdoutpipe[0], stdoutpipe[1]);
		fcntl(stdoutpipe[PIPE_READ], F_SETFD, FD_CLOEXEC);
		fcntl(stdoutpipe[PIPE_WRITE], F_SETFD, FD_CLOEXEC);

		stdout_args->fd = args->stdoutfd;
		stdout_args->stream_id = STDOUT_FILENO;
		stdout_args->channel = args->channel;
		stdout_args->device_handle = args->device_handle;
		stdout_args->done = &stdout_event;
		stdout_args->closepipe = stdoutpipe[PIPE_READ];

		stdoutccc_args->closepipe = stdoutpipe[PIPE_WRITE];
		stdoutccc_args->channel = args->channel;
		rc = novacom_set_closechannel_callback(args->device_handle, args->channel, channel_closefd_callback, stdoutccc_args);
		if(rc < 0) {
			platform_free(stdoutccc_args);
			stdoutccc_args = NULL;
		}

		platform_create_thread(NULL, &reader_worker_thread, (void *)stdout_args);
	} else {
		platform_event_signal(&stdout_event);
	}

	/* stderr */
	if( (args->stderrfd != -1) && (pipe(stderrpipe) == 0) ){
		stderrccc_args = platform_calloc(sizeof(channel_closefd_callback_args_t));
		platform_assert(stderrccc_args);
		stderr_args = platform_calloc(sizeof(fd_reader_args_t));
		platform_assert(stderr_args);

		LTRACEF("STDERRPIPE: open %d/%d\n", stderrpipe[0], stderrpipe[1]);
		fcntl(stderrpipe[PIPE_READ], F_SETFD, FD_CLOEXEC);
		fcntl(stderrpipe[PIPE_WRITE], F_SETFD, FD_CLOEXEC);

		stderr_args->fd = args->stderrfd;
		stderr_args->stream_id = STDERR_FILENO;
		stderr_args->channel = args->channel;
		stderr_args->device_handle = args->device_handle;
		stderr_args->done = &stderr_event;
		stderr_args->closepipe = stderrpipe[PIPE_READ];

		stderrccc_args->closepipe = stderrpipe[PIPE_WRITE];
		stderrccc_args->channel = args->channel;
		rc = novacom_set_closechannel_callback(args->device_handle, args->channel, channel_closefd_callback, stderrccc_args);
		if (rc < 0) {
			platform_free(stderrccc_args);
			stderrccc_args = NULL;
		}

		platform_create_thread(NULL, &reader_worker_thread, (void *)stderr_args);
	} else {
		platform_event_signal(&stderr_event);
	}

	/* stdin */
	if (args->stdinfd != -1) {
		stdin_args = platform_calloc(sizeof(struct fd_writer_args));
		platform_assert(stdin_args);

		out_queue = bufq_create();  /* save for later, so we can shut it down if the process dies */

		stdin_args->fd = args->stdinfd;
		stdin_args->in_queue = out_queue;
		stdin_args->channel = args->channel;
		stdin_args->device_handle = args->device_handle;
		stdin_args->done = &stdin_event;
		platform_create_thread(NULL, &writer_worker_thread, (void *)stdin_args);
	} else {
		platform_event_signal(&stdin_event);
	}

	/* packet thread */
	struct packet_thread_args *pt_args = platform_alloc(sizeof(struct packet_thread_args));
	platform_assert(pt_args);

	pt_args->done = &packet_event;
	pt_args->in_queue = input_queue;
	pt_args->out_queue = out_queue;
	pt_args->child = args->child;
	pt_args->stdoutpipe = stdoutpipe[PIPE_WRITE];
	pt_args->stderrpipe = stderrpipe[PIPE_WRITE];
	pt_args->stdoutfd = args->stdoutfd;
	platform_create_thread(NULL, &packet_thread, (void *)pt_args);

	/* now we're running */

	/* wait for any stdout thread to exit */
	LTRACEF("waiting on stdout_event\n");
	platform_event_wait(&stdout_event);
	platform_event_destroy(&stdout_event);
	if(stdout_args) {
		if(stdout_args->rcode) {
			returncode = stdout_args->rcode; /* pickup stdout ret code */
		}
		platform_free(stdout_args);
		stdout_args = NULL;
	}
	if(stdoutpipe[0] != -1) {
		close(stdoutpipe[PIPE_WRITE]);
		close(stdoutpipe[PIPE_READ]);
		//LTRACEF("STDOUTPIPE: close %d/%d\n", stdoutpipe[0], stdoutpipe[1]);
	}
	if(stdoutccc_args) {
		novacom_clear_closechannel_callback(args->device_handle, args->channel, channel_closefd_callback, stdoutccc_args);
	}

	/* wait for any stderr thread to exit */
	LTRACEF("waiting on stderr_event\n");
	platform_event_wait(&stderr_event);
	platform_event_destroy(&stderr_event);
	if(stderr_args) {
		if(!returncode && stderr_args->rcode) {
			returncode = stderr_args->rcode; /* pickup stderr ret code */
		}
		platform_free(stderr_args);
	}
	if(stderrpipe[0] != -1) {
		close(stderrpipe[PIPE_WRITE]);
		close(stderrpipe[PIPE_READ]);
		//LTRACEF("STDERRPIPE: close %d/%d\n", stderrpipe[0], stderrpipe[1]);
	}
	if(stderrccc_args) {
		novacom_clear_closechannel_callback(args->device_handle, args->channel, channel_closefd_callback, stderrccc_args);
	}

	/* wait for process to terminate either on its own accord or via a signal we delivered it */
	if (args->child > 0) {
		LTRACEF("waiting on pid %d\n", args->child);
		waitpid(args->child, &rc, 0);
		LTRACEF("waited on pid %d\n", args->child);

		/* signal stdin thread to terminate via closing queue */
		if (out_queue) {
			bufq_close(out_queue);
		}
	} else if (args->stdout_lead) {
		/*stdout already closed, initiate channel close */
		if (out_queue) {
			/* signal stdin thread to terminate via closing queue */
			bufq_close(out_queue);
		}
	}

	/* wait for any stdin thread to exit */
	LTRACEF("waiting on stdin_event\n");
	platform_event_wait(&stdin_event);
	platform_event_destroy(&stdin_event);
	if(stdin_args) {
		if(!returncode && stdin_args->rcode) {
			returncode = stdin_args->rcode; /* pickup stdin ret code */
		}
		platform_free(stdin_args);
	}

	/* send the return code before the channel is destroyed */
	if (args->child > 0)  {
		LTRACEF("sending return code %d\n", rc);
		returncode = WEXITSTATUS(rc);
	}
	send_packet_returncode(args->device_handle, args->channel, returncode);

	/* shut down the channel */
	LTRACEF("closing novacom channel\n");
	novacom_close_channel(args->device_handle, args->channel);

	/* wait for the packetization thread to shut down, may have been triggered by channel close */
	LTRACEF("waiting on packet_event\n");
	//this is the last chance to close input_queue:
	rc = platform_event_wait_timeout(&packet_event, 60000); //timeout in 60 sec
	if (rc) { //to close input_queue and wait again
		if (input_queue) {
			bufq_close(input_queue);
		}
		platform_event_wait(&packet_event);
	}
	//
	platform_event_destroy(&packet_event);

	/* kill the packet bufq */
	if (out_queue)
		bufq_destroy(out_queue);

error:
	//Kill the input queue
	if(input_queue) {
		bufq_destroy(input_queue);
	}
	//release devicehandle
	novacom_release_device_handle(args->device_handle);
	/* free our args and get out of here */
	platform_free(arg);
	LTRACEF("exiting\n");

	return NULL;
}

start_fds_args_t *devcmd_alloc_startfdargs(device_handle_t device_handle, int channel)
{
	start_fds_args_t *sfd_args = platform_calloc(sizeof(start_fds_args_t));
	platform_assert(sfd_args);
	sfd_args->stdinfd = -1;
	sfd_args->stderrfd = -1;
	sfd_args->stdoutfd = -1;
	sfd_args->device_handle = device_handle;
	sfd_args->channel = channel;

	return sfd_args;
}

/* handles get command */
static void novacom_start_file_send(device_handle_t device_handle, int channel, const char *path, const char **args)
{
	// start_fds_thread
	start_fds_args_t *sfd_args = devcmd_alloc_startfdargs(device_handle, channel);

	sfd_args->stdoutfd = open(path, O_RDONLY);
	if (sfd_args->stdoutfd == -1) {
		const char *response = "file open failed\n";
		novacom_write_channel_async(device_handle, channel, response, strlen(response) + 1, 0, NULL, NULL);
		platform_free(sfd_args);
		return;
	}
	fcntl(sfd_args->stdoutfd, F_SETFD, FD_CLOEXEC);

	//Will be unretained by the start_fds_thread
	novacom_retain_device_handle(device_handle);
	platform_create_thread(NULL, &start_fds_thread, (void *)sfd_args);
}

/* handles put command */
static void novacom_start_file_receive(device_handle_t device_handle, int channel, const char *path, const char **args)
{
	// start_fds_thread
	start_fds_args_t *sfd_args = devcmd_alloc_startfdargs(device_handle, channel);

	sfd_args->stdinfd = open(path, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
	if (sfd_args->stdinfd == -1) {
		const char *response = "file open failed\n";
		novacom_write_channel_async(device_handle, channel, response, strlen(response) + 1, 0, NULL, NULL);
		platform_free(sfd_args);
		return;
	}
	fcntl(sfd_args->stdinfd, F_SETFD, FD_CLOEXEC);
	//Will be unretained by the start_fds_thread
	novacom_retain_device_handle(device_handle);
	platform_create_thread(NULL, &start_fds_thread, (void *)sfd_args);
}

struct tcp_connect_args {
	device_handle_t device_handle;
	int channel;
	char *port;
};

static void *tcp_connect_thread(void *arg)
{
	device_pthread_setaffinity();

	struct tcp_connect_args *args = (struct tcp_connect_args *)arg;
	int sock = -1;
	int err;
	struct addrinfo *res = NULL;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ALL|AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo("localhost", args->port, &hints, &res);
	if (err < 0) goto failure;

	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock == -1) goto failure;
	fcntl(sock, F_SETFD, FD_CLOEXEC);

	err = connect(sock, res->ai_addr, res->ai_addrlen);
	if (err != 0) goto failure;

	freeaddrinfo(res);
	res = NULL;

	// start_fds_thread
	start_fds_args_t *sfd_args = devcmd_alloc_startfdargs(args->device_handle, args->channel);
	sfd_args->stdinfd = dup(sock);
	fcntl(sfd_args->stdinfd, F_SETFD, FD_CLOEXEC);
	sfd_args->stdoutfd = dup(sock);
	fcntl(sfd_args->stdoutfd, F_SETFD, FD_CLOEXEC);
	sfd_args->stdout_lead = 1;

	platform_create_thread(NULL, &start_fds_thread, (void *)sfd_args);

	goto exit;
failure:
	{
		const char *response = "socket open failed\n";
		novacom_write_channel_async(args->device_handle, args->channel, response, strlen(response) +1, 0, NULL, NULL);
		//release it here as the start_fds_thread did not get executed.
		novacom_release_device_handle(args->device_handle);
	}
exit:
	if (res) freeaddrinfo(res);
	if (sock != -1) close(sock);
	platform_free(args->port);
	platform_free(args);
	return NULL;
}

static void novacom_start_tcp_connect(device_handle_t device_handle, int channel, const char *port, const char **args)
{
	// tcp_connect: need this in a separate thread to avoid timeouts
	struct tcp_connect_args *tc_args = platform_alloc(sizeof(struct tcp_connect_args));
	platform_assert(tc_args);
	tc_args->device_handle = device_handle;
	tc_args->channel = channel;
	tc_args->port = platform_strdup(port);

	novacom_retain_device_handle(device_handle);
	platform_create_thread(NULL, &tcp_connect_thread, (void *)tc_args);
}

#if DEVICE
static void novacom_spawn_shell(device_handle_t device_handle, int channel, const char *path, const char **args)
{
	// launch the shell
	int pty;

	// We only ever spawn a shell on a pty. if we need to spawn
	// something else on a pty, we can break this out.
	path = "/bin/sh";
	LTRACEF("channel %d, path '%s'\n", channel, path);

	const char *newargs[3] = { path, "-l", NULL };
	args = newargs;

	pty = posix_openpt(O_RDWR | O_NOCTTY);
	fcntl(pty, F_SETFD, FD_CLOEXEC);

//	TRACEF("pty %d\n", pty);

	char ptsname[256];

	ptsname_r(pty, ptsname, sizeof(ptsname));

	LTRACEF("ptsname %s\n", ptsname);

	grantpt(pty);
	unlockpt(pty);

	platform_mutex_lock(&fork_mutex);

	pid_t pid;
	if ((pid = fork()) == 0) {
		int rc;
		uid_t uid;

		device_process_setaffinity();

		struct passwd *pw = NULL;

		int slavepty = open(ptsname, O_RDWR);
		if(slavepty == -1) {
			goto ch_exit;
		}
		fcntl(slavepty, F_SETFD, FD_CLOEXEC);

//		TRACEF("slavepty %d\n", slavepty);

		// detach from our current tty, ignore result(may produce ENOTTY)
		(void)ioctl(STDOUT_FILENO, TIOCNOTTY);

		// child
		close(0);
		close(1);
		close(2);

		rc = dup2(slavepty, STDIN_FILENO);
		if(rc == -1) {
			goto ch_exit;
		}
		rc = dup2(slavepty, STDOUT_FILENO);
		if(rc == -1) {
			goto ch_exit;
		}
		rc = dup2(slavepty, STDERR_FILENO);
		if(rc == -1) {
			goto ch_exit;
		}
		close(slavepty);
		close(pty);

		// create a new session
		setsid();

		// set the current pty as the controlling tty
		rc = ioctl(STDOUT_FILENO, TIOCSCTTY, 0);
		if(rc == -1) {
			TRACEL(LOG_ERROR, "unable to set tty, errno %d\n", errno);
			goto ch_exit;
		}

		/* Go back to the normal scheduler */
		struct sched_param params;
		params.sched_priority = sched_get_priority_max(SCHED_OTHER);
		rc = sched_setscheduler(getpid(), SCHED_OTHER, &params);
		if (rc) {
			log_printf(LOG_ERROR, "Error calling sched_setscheduler(): %d\n", rc);
		}
		/* Higher then your average process */
		setpriority(PRIO_PROCESS, 0, -1);

		/* environment (inherited from current user) */
		uid = getuid();
		pw = getpwuid(uid);

		if (pw && pw->pw_name) {
			(void) setenv("USER", pw->pw_name, 1);
			(void) setenv("LOGNAME", pw->pw_name, 1);
			if(pw->pw_dir) {
				(void) setenv("HOME", pw->pw_dir, 1);
			}
			(void) setenv("SHELL", path, 1);
		}

		/*start cmd */
		if( 0 == chdir("/") ) {
			execv(path, (void *)args);
		}
ch_exit:
		exit(-1);
	}

	platform_mutex_unlock(&fork_mutex);

	// start_fds_thread
	start_fds_args_t *sfd_args = devcmd_alloc_startfdargs(device_handle, channel);

	sfd_args->stdoutfd = dup(pty);
	fcntl(sfd_args->stdoutfd, F_SETFD, FD_CLOEXEC);
	sfd_args->stdinfd = dup(pty);
	fcntl(sfd_args->stdinfd, F_SETFD, FD_CLOEXEC);
	sfd_args->child = pid;
	close(pty);

	//Will be unretained by the start_fds_thread
	novacom_retain_device_handle(device_handle);
	platform_create_thread(NULL, &start_fds_thread, (void *)sfd_args);
}

static void novacom_spawn_process(device_handle_t device_handle, int channel, const char *path, const char **args)
{
	int rc;
	int stdinfds[2]  = { -1, -1};
	int stdoutfds[2] = { -1, -1};
	int stderrfds[2] = { -1, -1};
	int arg_count = 0;
	struct stat fstat;
	const char *errstr = NULL;

	//check if exists
	memset(&fstat, 0, sizeof(fstat));
	rc = stat(path, &fstat);

	if(rc == -1) {
		if(errno == ENOENT) {
			errstr = "file does not exist\n";
		} else {
			errstr = "problem with path\n";
		}
	}
	else {
		if (!((fstat.st_mode & (S_IFLNK | S_IFREG)) && (fstat.st_mode & (S_IXUSR | S_IXGRP)))) {
    			errstr = "not an executable file\n";
        	}
	}
		
	if (errstr) {
		TRACEF("file %s: %s\n", path, errstr);
		novacom_write_channel_async(device_handle, channel, errstr, strlen(errstr) + 1, 0, NULL, NULL);
		return;
	}
	// extract arguments, count last NULL arg as well
	while(args && args[arg_count++]) {
	}
	const char **execargs = platform_calloc((arg_count + 2)*(sizeof(char *))); /* +1 path +2 null arg */
	platform_assert(execargs);

	// launch the process...
	LTRACEF("channel %d of device %p, path '%s', args %p\n", channel, device_handle, path, args);

	rc = pipe(stdinfds);
	if(rc == -1) {
		goto error;
	}
	fcntl(stdinfds[PIPE_READ], F_SETFD, FD_CLOEXEC);
	fcntl(stdinfds[PIPE_WRITE], F_SETFD, FD_CLOEXEC);
	rc = pipe(stdoutfds);
	if(rc == -1) {
		goto error;
	}
	fcntl(stdoutfds[PIPE_READ], F_SETFD, FD_CLOEXEC);
	fcntl(stdoutfds[PIPE_WRITE], F_SETFD, FD_CLOEXEC);
	rc = pipe(stderrfds);
	if(rc == -1) {
		goto error;
	}
	fcntl(stderrfds[PIPE_READ], F_SETFD, FD_CLOEXEC);
	fcntl(stderrfds[PIPE_WRITE], F_SETFD, FD_CLOEXEC);

	platform_mutex_lock(&fork_mutex);

	pid_t pid;
	if ((pid = fork()) == 0) {
		int rc;
		// child
		device_process_setaffinity();

		close(0);
		close(1);
		close(2);

		rc = dup2(stdinfds[PIPE_READ], STDIN_FILENO);
		if(rc == -1) {
			goto ch_exit;
		}
		rc = dup2(stdoutfds[PIPE_WRITE], STDOUT_FILENO);
		if(rc == -1) {
			goto ch_exit;
		}
		rc = dup2(stderrfds[PIPE_WRITE], STDERR_FILENO);
		if(rc == -1) {
			goto ch_exit;
		}

		/* copy args over, inserting path in the first slot */
		int i;
		execargs[0] = path;
		for (i = 0; i < arg_count; i++) {
			execargs[i+1] = args[i];
		}

		/* create a simple subprocess directly, not a session leader */
		setpgrp();

		/* Go back to the normal scheduler */
		struct sched_param params;
		params.sched_priority = sched_get_priority_max(SCHED_OTHER);
		rc = sched_setscheduler(getpid(), SCHED_OTHER, &params);
		if (rc) {
			log_printf(LOG_ERROR, "Error calling sched_setscheduler(): %d\n", rc);
		}
		/* Higher then your average process */
		setpriority(PRIO_PROCESS, 0, -1);

		if( 0 == chdir("/") ) {
			execv(path, (void *)execargs);
		}
ch_exit:
		/* free memory */
		platform_free(execargs);
		/* exec fell through */
		exit(1);
	}

	platform_mutex_unlock(&fork_mutex);
	platform_free(execargs);

	close(stdinfds[PIPE_READ]);
	close(stdoutfds[PIPE_WRITE]);
	close(stderrfds[PIPE_WRITE]);

	// start_fds_thread
	start_fds_args_t *sfd_args = devcmd_alloc_startfdargs(device_handle, channel);
	sfd_args->stdinfd = stdinfds[PIPE_WRITE];
	sfd_args->stdoutfd = stdoutfds[PIPE_READ];
	sfd_args->stderrfd = stderrfds[PIPE_READ];
	sfd_args->child = pid;

	//Will be unretained by the start_fds_thread
	novacom_retain_device_handle(device_handle);
	platform_create_thread(NULL, &start_fds_thread, (void *)sfd_args);
	
	return;

error:
	log_printf(LOG_ERROR, "Error: %d(errno=%d)\n", rc, errno);
	close(stdinfds[PIPE_READ]);
	close(stdinfds[PIPE_WRITE]);
	close(stdoutfds[PIPE_READ]);
	close(stdoutfds[PIPE_WRITE]);
	close(stderrfds[PIPE_READ]);
	close(stderrfds[PIPE_WRITE]);
	if(execargs) {
		platform_free(execargs);
	}
	return;
}

#endif // DEVICE

// === Command stuff here ===


static struct {
	char* verb;
	char* scheme;
	void (*spawn)(device_handle_t device_handle, int chan, const char *path, const char **args);
} iohandlers[] =
{
	{ "get", "file", novacom_start_file_send },
	{ "put", "file", novacom_start_file_receive },
	// no non-packet version of this, unless someone can think of a good reason
	{ "connect", "tcp-port", novacom_start_tcp_connect },
#if DEVICE
	{ "open", "tty", novacom_spawn_shell },
	{ "run", "file", novacom_spawn_process },
#endif
	{ NULL, NULL, NULL }
};

static int novacom_handle_command_fromclient(device_handle_t device_handle, uint32_t chan, int err, const void *buf, size_t len, void *cookie)
{
	int i=0;
	bool handled = false;

	if (err < 0)
		return 0;

#if DEVICE
	// check mode
	handled = auth_is_done();
	if ( false == handled ) {
		const char *response = "req:auth\n";
		novacom_write_channel_async(device_handle, chan, response, strlen(response) + 1, 0, NULL, NULL);
		return 0;
	}
#endif

	// parse the command
	struct novacom_command_url *url = NULL;
	if (parse_command(buf, len, &url) < 0) {
		const char *response = "unrecognized command\n";
		novacom_write_channel_async(device_handle, chan, response, strlen(response) + 1, 0, NULL, NULL);
		return 0;
	}

	// unregister the command handler up front so that fast clients don't overrun us
	novacom_set_read_callback(device_handle, chan, NULL, NULL);

	handled = false;
	while (iohandlers[i].verb != NULL) {
		if ((strcasecmp(url->verb, iohandlers[i].verb) == 0) &&
				strcasecmp(url->scheme, iohandlers[i].scheme) == 0) {
			iohandlers[i].spawn(device_handle, chan, url->path, (const char **)(url->args));
			handled = true;
			break;
		}
		i++;
	}
	if (!handled) {
		const char *response = "unrecognized command\n";
		novacom_write_channel_async(device_handle, chan, response, strlen(response) + 1, 0, NULL, NULL);
		novacom_set_read_callback(device_handle, chan, &novacom_handle_command_fromclient, NULL);
	}

	if(url) {
		platform_free(url->args);
		platform_free(url->verbargs);
		platform_free(url->string);
		platform_free(url);
	}

	return 0;
}

int novacom_setup_command(device_handle_t device_handle, uint32_t chan)
{
	novacom_set_read_callback(device_handle, chan, &novacom_handle_command_fromclient, NULL);

	return 0;
}

