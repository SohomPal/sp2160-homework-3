#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/select.h>
#include "logger.h"

// Default values
#define DEFAULT_MULTICAST_IP "239.0.0.1"
#define DEFAULT_PORT 12345
#define MAX_USER_ID_LEN 32
#define COMMAND_INTERVAL 5  // Interval for re-sending SET_INTERVAL command
#define MAX_MSG_LEN 1024

// Global variables
char user_id[MAX_USER_ID_LEN];
char multicast_ip[16];  // IPv4 address string
int port;
int is_controller;
int heartbeat_interval;
int sockfd;
time_t last_interval_command_time;

void print_usage(const char *program_name) {
    printf("Usage: %s <user_id> [options]\n", program_name);
    printf("Options:\n");
    printf("  -m <multicast_ip> or --multicast-ip=<multicast_ip>: Override default multicast IP (239.0.0.1)\n");
    printf("  -p <port> or --port=<port>: Override default port (12345)\n");
    printf("  -c <initial_interval>: Start as controller with specified heartbeat interval (0-30)\n");
    exit(EXIT_FAILURE);
}

int parse_arguments(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
    }

    // Set default values
    strncpy(multicast_ip, DEFAULT_MULTICAST_IP, sizeof(multicast_ip) - 1);
    port = DEFAULT_PORT;
    is_controller = 0;
    heartbeat_interval = 0;

    // Copy user_id
    if (strlen(argv[1]) >= MAX_USER_ID_LEN) {
        fprintf(stderr, "Error: user_id must be less than %d characters\n", MAX_USER_ID_LEN);
        return -1;
    }
    strncpy(user_id, argv[1], MAX_USER_ID_LEN - 1);
    user_id[MAX_USER_ID_LEN - 1] = '\0';

    // Parse options
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 || strncmp(argv[i], "--multicast-ip=", 15) == 0) {
            const char *ip;
            if (strcmp(argv[i], "-m") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "Error: Missing multicast IP address\n");
                    return -1;
                }
                ip = argv[++i];
            } else {
                ip = argv[i] + 15;
            }
            strncpy(multicast_ip, ip, sizeof(multicast_ip) - 1);
        }
        else if (strcmp(argv[i], "-p") == 0 || strncmp(argv[i], "--port=", 7) == 0) {
            const char *port_str;
            if (strcmp(argv[i], "-p") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "Error: Missing port number\n");
                    return -1;
                }
                port_str = argv[++i];
            } else {
                port_str = argv[i] + 7;
            }
            port = atoi(port_str);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Error: Invalid port number\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "-c") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing heartbeat interval\n");
                return -1;
            }
            heartbeat_interval = atoi(argv[++i]);
            if (heartbeat_interval < 0 || heartbeat_interval > 30) {
                fprintf(stderr, "Error: Heartbeat interval must be between 0 and 30\n");
                return -1;
            }
            is_controller = 1;
        }
        else {
            fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

// Function to set up multicast socket
int setup_multicast_socket() {
    struct sockaddr_in addr;
    struct ip_mreq mreq;
    
    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        return -1;
    }

    // Allow multiple sockets to use the same port
    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        return -1;
    }

    // Allow multiple processes to bind to the same port
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEPORT failed");
        return -1;
    }

    // Set up multicast
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    // Bind to the port
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        return -1;
    }

    // Join multicast group
    mreq.imr_multiaddr.s_addr = inet_addr(multicast_ip);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt IP_ADD_MEMBERSHIP failed");
        return -1;
    }

    // Set multicast TTL
    int ttl = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt IP_MULTICAST_TTL failed");
        return -1;
    }

    // Set multicast interface
    struct in_addr local_interface;
    local_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, &local_interface, sizeof(local_interface)) < 0) {
        perror("setsockopt IP_MULTICAST_IF failed");
        return -1;
    }

    return 0;
}

// send heartbeat message if controller function
void send_heartbeat(int sockfd, FILE *log_file) {
    char message[1024];
    snprintf(message, sizeof(message), "Heartbeat from %s", user_id);

    // send message to multicast group
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(multicast_ip);
    dest_addr.sin_port = htons(port);

    // send message
    if (sendto(sockfd, message, strlen(message), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
    }

    // log message
    log_message(log_file, user_id, "Sent heartbeat message");
}

// receive heartbeat messages
void receive_heartbeats(int sockfd, FILE *log_file) {
    char buffer[1024];
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);

    // receive message
    ssize_t num_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_addr, &sender_len);
    if (num_bytes < 0) {
        perror("recvfrom");
        return;
    }

    // print message
    printf("Received heartbeat from %s\n", inet_ntoa(sender_addr.sin_addr));

    // log message
    log_message(log_file, user_id, "Received heartbeat from %s", inet_ntoa(sender_addr.sin_addr));
}

// Function to send multicast message
void send_multicast_message(const char *message) {
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(multicast_ip);
    dest_addr.sin_port = htons(port);

    if (sendto(sockfd, message, strlen(message), 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
    }
}

// Function to send SET_INTERVAL command
void send_interval_command(int interval, FILE *log_file) {
    char message[MAX_MSG_LEN];
    snprintf(message, sizeof(message), "SET_INTERVAL %d", interval);
    
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(multicast_ip);
    dest_addr.sin_port = htons(port);

    if (sendto(sockfd, message, strlen(message), 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        return;
    }

    log_message(log_file, user_id, "Sent SET_INTERVAL command with value %d", interval);
    last_interval_command_time = time(NULL);
}

// Function to send CONTROLLER_DOWN command
void send_controller_down(FILE *log_file) {
    char message[] = "CONTROLLER_DOWN";
    
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(multicast_ip);
    dest_addr.sin_port = htons(port);

    if (sendto(sockfd, message, strlen(message), 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        return;
    }

    log_message(log_file, user_id, "Sent CONTROLLER_DOWN command");
}

// Function to handle controller input
void handle_controller_input(FILE *log_file) {
    char input[MAX_MSG_LEN];
    if (fgets(input, sizeof(input), stdin) != NULL) {
        input[strcspn(input, "\n")] = 0;  // Remove newline

        if (strcmp(input, "exit") == 0) {
            log_message(log_file, user_id, "Relinquishing controller role");
            send_controller_down(log_file);
            send_multicast_message("BYE");
            fclose(log_file);
            close(sockfd);
            exit(EXIT_SUCCESS);
        }
        else if (strcmp(input, "abort") == 0) {
            fclose(log_file);
            abort();
        }
        else {
            // Try to parse as interval
            int new_interval;
            if (sscanf(input, "%d", &new_interval) == 1) {
                if (new_interval >= 0 && new_interval <= 30) {
                    log_message(log_file, user_id, "User set interval to %d", new_interval);
                    heartbeat_interval = new_interval;
                    send_interval_command(new_interval, log_file);
                } else {
                    fprintf(stderr, "Error: Interval must be between 0 and 30\n");
                }
            }
        }
    }
}


int main(int argc, char *argv[]) {
    if (parse_arguments(argc, argv) != 0) {
        return EXIT_FAILURE;
    }

    // Print configuration
    printf("Configuration:\n");
    printf("User ID: %s\n", user_id);
    printf("Multicast IP: %s\n", multicast_ip);
    printf("Port: %d\n", port);
    printf("Mode: %s\n", is_controller ? "Controller" : "Client");
    if (is_controller) {
        printf("Initial Heartbeat Interval: %d\n", heartbeat_interval);
    }

    // Set up multicast socket
    if (setup_multicast_socket() < 0) {
        fprintf(stderr, "Failed to set up multicast socket\n");
        return EXIT_FAILURE;
    }

    // create log file in append mode
    char log_filename[64] = "heartbeat_app_";
    strcat(log_filename, user_id);
    strcat(log_filename, ".log");
    FILE *log_file = fopen(log_filename, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return EXIT_FAILURE;
    }

    // Initialize last interval command time
    last_interval_command_time = time(NULL);

    // main loop
    while (1) {
        if (is_controller) {
            fd_set read_fds;
            struct timeval tv;
            
            FD_ZERO(&read_fds);
            FD_SET(sockfd, &read_fds);
            FD_SET(STDIN_FILENO, &read_fds);

            // Set timeout for select
            tv.tv_sec = 1;  // Check every second
            tv.tv_usec = 0;

            if (select(sockfd + 1, &read_fds, NULL, NULL, &tv) < 0) {
                perror("select failed");
                break;
            }

            // Handle socket input
            if (FD_ISSET(sockfd, &read_fds)) {
                receive_heartbeats(sockfd, log_file);
            }

            // Handle user input
            if (FD_ISSET(STDIN_FILENO, &read_fds)) {
                handle_controller_input(log_file);
            }

            // Check if we need to resend the interval command
            time_t current_time = time(NULL);
            if (current_time - last_interval_command_time >= COMMAND_INTERVAL) {
                send_interval_command(heartbeat_interval, log_file);
            }

            // Send heartbeat
            send_heartbeat(sockfd, log_file);
            sleep(heartbeat_interval);
        } else {
            receive_heartbeats(sockfd, log_file);
        }
    }

    // close socket
    close(sockfd);
    fclose(log_file);
    return EXIT_SUCCESS;
}