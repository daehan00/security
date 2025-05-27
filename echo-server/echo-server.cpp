#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <vector>
#include <mutex>
#include <algorithm>

#include "myQueue.h"

void myerror(const char* msg) { fprintf(stderr, "%s %s %d\n", msg, strerror(errno), errno); }

void usage() {
    printf("<echo server>\n");
    printf("syntax : echo-server <port> [-e[-b]]\n");
    printf("  -e : echo mode\n");
    printf("  -b : broadcast to all connected clients (requires -e)\n");
    printf("sample: echo-server 1234 -e -b\n");
}

std::vector<std::shared_ptr<myQueue>> broadcastQueues;
std::mutex queuesMutex;

struct Param {
    bool echo{false};
    bool broadcast{false};
    uint16_t port{0};

    bool parse(int argc, char* argv[]) {
        for (int i = 1; i < argc;) {
            if (strcmp(argv[i], "-e") == 0) {
                echo = true;
                i++;
                continue;
            }

            if (strcmp(argv[i], "-b") == 0) {
                if (!echo) {
                    fprintf(stderr, "-b option requires -e option.\n");
                    return false;
                }

                broadcast = true;
                i++;
                continue;
            }

            if (port == 0 && i < argc) {
                port = atoi(argv[i]);
                i++;
                continue;
            }

            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return false;
        }

        return port != 0;
    }
} param;

void brcastThread(int sd, std::shared_ptr<myQueue> clientQueue) {
    while (true) {
        std::string msg = clientQueue->dequeue();
        ssize_t res = ::send(sd, msg.c_str(), msg.size(), 0);
        if (res == 0 || res == -1) break;
    }
    ::close(sd);
}

void recvThread(int sd, std::shared_ptr<myQueue> clientQueue = nullptr) {
	printf("connected\n");
	fflush(stdout);
	static const int BUFSIZE = 65536;
	char buf[BUFSIZE];

    std::thread bThread;
    bool isBroadcast = param.echo && param.broadcast;

    if (isBroadcast) {
        bThread = std::thread(brcastThread, sd, clientQueue);
    }

	while (true) {
		ssize_t res = ::recv(sd, buf, BUFSIZE - 1, 0);
		if (res == 0 || res == -1) {
			fprintf(stderr, "recv return %zd", res);
			myerror(" ");
			break;
		}

		buf[res] = '\0';
		printf("%s", buf);
		fflush(stdout);

		if (param.echo) {
            if (param.broadcast) {
                std::lock_guard<std::mutex> lock(queuesMutex);
                for (auto& q : broadcastQueues) {
                    q->enqueue(std::string(buf, res));
                }
            } else {
                res = ::send(sd, buf, res, 0);
                if (res == 0 || res == -1) {
                    fprintf(stderr, "send return %zd", res);
                    myerror(" ");
                    break;
                }
            }
		}
	}
	printf("disconnected\n");
	fflush(stdout);

    if (isBroadcast && queueSendThread.joinable())
        queueSendThread.detach();

    if (isBroadcast) {
        std::lock_guard<std::mutex> lock(queuesMutex);
        broadcastQueues.erase(
            std::remove(broadcastQueues.begin(), broadcastQueues.end(), clientQueue),
            broadcastQueues.end()
            );
    }

	::close(sd);
}

int main(int argc, char* argv[]) {
	if (!param.parse(argc, argv)) {
		usage();
		return -1;
	}

	//
	// socket
	//
	int sd = ::socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		myerror("socket");
		return -1;
	}

	//
	// setsockopt
	//
	{
		int optval = 1;
		int res = ::setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
		if (res == -1) {
			myerror("setsockopt");
			return -1;
		}
	}

	//
	// bind
	//
	{
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
		addr.sin_port = htons(param.port);

		ssize_t res = ::bind(sd, (struct sockaddr *)&addr, sizeof(addr));
		if (res == -1) {
			myerror("bind");
			return -1;
		}
	}

	//
	// listen
	//
	{
		int res = listen(sd, 5);
		if (res == -1) {
			myerror("listen");
			return -1;
		}
	}

	while (true) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int newsd = ::accept(sd, (struct sockaddr *)&addr, &len);
        if (newsd == -1) {
            myerror("accept");
            break;
        }

        if (param.echo && param.broadcast) {
            auto clientQueue = std::make_shared<myQueue>();
            {
                std::lock_guard<std::mutex> lock(queuesMutex);
                broadcastQueues.push_back(clientQueue);
            }
            std::thread* t = new std::thread(recvThread, newsd, clientQueue);
            t->detach();
        } else {
            std::thread* t = new std::thread(recvThread, newsd, nullptr);
            t->detach();
        }
	}
	::close(sd);
}
