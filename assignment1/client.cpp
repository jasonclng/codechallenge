#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

/* The main class for assignment submission protocol */
class SubmissionHandler {
  public:
    void run(const char* node, const char* service,
        const char* email, const char* password,
        const char* name, const char* repo);

  private:
    bool create_login_request(uint8_t* buf, int size,
        const char* email, const char* password);
    bool create_submission_request(uint8_t* buf, int size,
        const char* name, const char* email, const char* repo);
    bool create_logout_request(uint8_t* buf, int size);
    bool read_login_response(uint8_t* buf, int size);
    bool read_submission_response(uint8_t* buf, int size);
    bool read_logout_response(uint8_t* buf, int size);
    uint16_t checksum16(const uint8_t* buf, uint32_t len);
    const char* host;
    char service[11];
};

void SubmissionHandler::run(const char* node, const char* service,
        const char* email, const char* password, const char* name,
        const char* repo) {
    int sock;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *address;
    if (getaddrinfo(node, service, &hints, &address)) {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", errno);
        exit(1);
    }

    /* Lookup the given hostname and get the IP addresses */
    do {
        const int size = 256;
        uint8_t buffer[size];
        getnameinfo(address->ai_addr, address->ai_addrlen,
            (char*)buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST);
        printf("%s\n", buffer);

        /* Create a socket for each IP address and attempt to connect
           to the server */
        sock = socket(address->ai_family,
        address->ai_socktype, address->ai_protocol);

        if (sock > 0) {
            printf("Socket successfully created..\n");
            if (connect(sock, address->ai_addr, address->ai_addrlen))
                fprintf(stderr, "Error: %d %s\n", errno, strerror(errno));
            else {
                /* Start the assignment submission protocol if the server
                   can be connected successfully. */
                bool ret;

                /* Create Login Request */
                ret = create_login_request(buffer, size, email, password);
                if (ret) {
                    /* Send the Login Request and read the response.
                       Login Response will be received upon successful
                       login. Otherwise, Logout Response will be obtained
                       with the failure reason */
                    send(sock, buffer, 109, 0);
                    printf("Login request sent\n");
                    int bytes_read = read(sock, buffer, size);
                    ret = read_login_response(buffer, bytes_read);
                    if (ret) {
                        /* Create Submission Request */
                        ret = create_submission_request(buffer, size,
                                  name, email, repo);
                        if (ret) {
                            /* Send the Submission Request and get the
                               Submission Response. A token ID will be returned
                               upon successful submission. */
                            send(sock, buffer, 205, 0);
                            int bytes_read = read(sock, buffer, size);
                            ret = read_submission_response(buffer, bytes_read);
                            if (ret) {
                                printf("Submission success.\n");
                                const char* token = (char*)&buffer[13];
                                printf("Token:\n");
                                printf("%s\n", token);
                                /* Create Logout Request */
                                ret = create_logout_request(buffer, size);
                                if (ret) {
                                   /* Send the Logout Response and get the Logout
                                      Response. The Logout Response contains the
                                      logout reason. */
                                    send(sock, buffer, 13, 0);
                                    int bytes_read = read(sock, buffer, size);
                                    ret = read_logout_response(buffer, bytes_read);
                                    if (ret) {
                                        const char* reason = (char*)&buffer[13];
                                        printf("%s\n", reason);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            close(sock);
        }
    } while ((address = address->ai_next));
}

bool SubmissionHandler::create_login_request(uint8_t* buf, int size,
        const char* email, const char* password) {
    const int msg_len = 109;
    if (size < msg_len) {
        fprintf(stderr, "Failed to create login request. Buffer size too small.\n");
        return false;
    }
    memset(buf, 0, msg_len);

    /* MsgType */
    buf[0] = 'L';

    /* MsgLen */
    memcpy(&buf[1], &msg_len, sizeof(msg_len));

    /* Timestamp */
    struct timespec res;
    clock_gettime(CLOCK_REALTIME, &res);
    uint64_t time = res.tv_nsec;
    memcpy(&buf[3], &time, sizeof(time));

    /* User */
    memcpy(&buf[13], email, strlen(email));

    /* Password */
    memcpy(&buf[77], password, strlen(password));

    /* ChkSum */
    uint16_t checksum = checksum16(buf, msg_len);
    memcpy(&buf[11], &checksum, 2);

    return true;
}

bool SubmissionHandler::create_submission_request(uint8_t* buf, int size,
        const char* name, const char* email, const char* repo) {
    const int msg_len = 205;
    if (size < msg_len) {
        fprintf(stderr, "Failed to create submission request. Buffer size too small.\n");
        return false;
    }
    memset(buf, 0, msg_len);

    /* MsgType */
    buf[0] = 'S';

    /* MsgLen */
    memcpy(&buf[1], &msg_len, sizeof(msg_len));

    /* Timestamp */
    struct timespec res;
    clock_gettime(CLOCK_REALTIME, &res);
    uint64_t time = res.tv_nsec;
    memcpy(&buf[3], &time, sizeof(time));

    /* User */
    memcpy(&buf[13], name, strlen(name));

    /* Email */
    memcpy(&buf[77], email, strlen(email));

    /* Repo */
    memcpy(&buf[141], repo, strlen(repo));

    /* ChkSum */
    uint16_t checksum = checksum16(buf, msg_len);
    memcpy(&buf[11], &checksum, 2);

    return true;
}

bool SubmissionHandler::create_logout_request(uint8_t* buf, int size) {
    const int msg_len = 13;
    if (size < msg_len) {
        fprintf(stderr, "Failed to create logout request. Buffer size too small.\n");
        return false;
    }
    memset(buf, 0, msg_len);

    /* MsgType */
    buf[0] = 'O';

    /* MsgLen */
    memcpy(&buf[1], &msg_len, sizeof(msg_len));

    /* Timestamp */
    struct timespec res;
    clock_gettime(CLOCK_REALTIME, &res);
    uint64_t time = res.tv_nsec;
    memcpy(&buf[3], &time, sizeof(time));

    /* ChkSum */
    uint16_t checksum = checksum16(buf, msg_len);
    memcpy(&buf[11], &checksum, 2);

    return true;
}

bool SubmissionHandler::read_login_response(uint8_t* buf, int size) {
    int offset = 0;
    while (offset < size) {
        uint8_t msg_type = buf[offset];
        uint16_t msg_len = *((uint16_t*)&buf[offset+1]);
        uint16_t checksum = *((uint16_t*)&buf[offset+11]);
    
        if (msg_type == 'E' && msg_len == 46) {
            memset((uint16_t*)&buf[offset+11], 0, sizeof(uint16_t));
            if (checksum16(&buf[offset], 46) == checksum && buf[offset+13] == 'Y') {
                printf("Login success\n");
                return true;
            }
        } else if (msg_type == 'G' && msg_len == 45) {
            fprintf(stderr, "Login failed with reason: %s\n", &buf[offset+13]);
        }

        offset += msg_len;
    }

    return false;
}

bool SubmissionHandler::read_submission_response(uint8_t* buf, int size) {
    int offset = 0;
    while (offset < size) {
        uint8_t msg_type = buf[offset];
        uint16_t msg_len = *((uint16_t*)&buf[offset+1]);
        uint16_t checksum = *((uint16_t*)&buf[offset+11]);
    
        if (msg_type == 'R' && msg_len == 45) {
            memset((uint16_t*)&buf[offset+11], 0, sizeof(uint16_t));
            if (checksum16(&buf[offset], 45) == checksum) {
                return true;
            }
        } else if (msg_type == 'G' && msg_len == 45) {
            fprintf(stderr, "Login failed with reason: %s\n", &buf[offset+13]);
        }

        offset += msg_len;
    }

    return false;
}

bool SubmissionHandler::read_logout_response(uint8_t* buf, int size) {
    int offset = 0;
    while (offset < size) {
        uint8_t msg_type = buf[offset];
        uint16_t msg_len = *((uint16_t*)&buf[offset+1]);
        uint16_t checksum = *((uint16_t*)&buf[offset+11]);
    
        if (msg_type == 'G' && msg_len == 45) {
            memset((uint16_t*)&buf[offset+11], 0, sizeof(uint16_t));
            if (checksum16(&buf[offset], 45) == checksum) {
                return true;
            }
        }

        offset += msg_len;
    }

    return false;
}

uint16_t SubmissionHandler::checksum16(const uint8_t* buf, uint32_t len) {
    uint32_t sum = 0;
    for (uint32_t j = 0; j < len - 1; j += 2) {
        sum += *((uint16_t*)(&buf[j]));
    }
    if ((len & 1) != 0) {
        sum += buf[len - 1];
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    return (uint16_t)(~sum);
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "%s <host> <port> <email> <password> <name> <repo>\n", argv[0]);
        exit(1);
    }

    /* Instantiate the submission handler and execute the main flow */
    SubmissionHandler handler;
    handler.run(argv[1], argv[2], argv[3],
        argv[4], argv[5], argv[6]);
}
