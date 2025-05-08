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
#include <signal.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>

// Default values
#define DEFAULT_MULTICAST_IP "239.0.0.1"
#define DEFAULT_PORT 12345
#define MAX_USER_ID_LEN 32
#define COMMAND_INTERVAL 5  // Interval for re-sending SET_INTERVAL command
#define MAX_MSG_LEN 1024
#define MISSED_HEARTBEAT_THRESHOLD 2  // Number of missed heartbeats before considering controller down

// Shared memory and mutex for controller status
#define SHM_NAME "/controller_status"
#define MUTEX_NAME "/controller_mutex"

typedef struct {
    int controllerActive;
    char controllerId[MAX_USER_ID_LEN];
} ControllerStatus;

ControllerStatus *controllerStatus = NULL;
pthread_mutex_t *controllerMutex = NULL;
int shmFd = -1;
int mutexFd = -1;

// Global variables
char user_id[MAX_USER_ID_LEN];
char multicast_ip[16];  // IPv4 address string
int port;
int is_controller;
int heartbeat_interval;
int sockfd;
time_t last_interval_command_time;
time_t last_controller_heartbeat;
int missed_heartbeats;
char current_controller_id[MAX_USER_ID_LEN];

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

// Function to send heartbeat message (for clients)
void send_heartbeat(FILE *log_file) {
    char message[MAX_MSG_LEN];
    snprintf(message, sizeof(message), "HEARTBEAT from %s", user_id);

    // send message to multicast group
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(multicast_ip);
    dest_addr.sin_port = htons(port);

    // send message
    if (sendto(sockfd, message, strlen(message), 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        return;
    }

    log_message(log_file, user_id, "Sent heartbeat message");
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

// Function to initialize shared memory and mutex
int init_shared_memory() {
    // Create or open shared memory for controller status
    shmFd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shmFd == -1) {
        perror("shm_open failed");
        return -1;
    }

    // Get the current size of the shared memory
    struct stat sb;
    if (fstat(shmFd, &sb) == -1) {
        perror("fstat failed");
        close(shmFd);
        shm_unlink(SHM_NAME);
        return -1;
    }

    // Only set size if this is a new shared memory object
    if (sb.st_size == 0) {
        if (ftruncate(shmFd, sizeof(ControllerStatus)) == -1) {
            perror("ftruncate failed");
            close(shmFd);
            shm_unlink(SHM_NAME);
            return -1;
        }
    }

    // Map shared memory
    controllerStatus = (ControllerStatus *)mmap(NULL, sizeof(ControllerStatus),
                                             PROT_READ | PROT_WRITE, MAP_SHARED,
                                             shmFd, 0);
    if (controllerStatus == MAP_FAILED) {
        perror("mmap failed");
        close(shmFd);
        shm_unlink(SHM_NAME);
        return -1;
    }

    // Create a process-shared mutex
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

    // Allocate mutex in shared memory
    controllerMutex = (pthread_mutex_t *)mmap(NULL, sizeof(pthread_mutex_t),
                                            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                                            -1, 0);
    if (controllerMutex == MAP_FAILED) {
        perror("mutex mmap failed");
        pthread_mutexattr_destroy(&attr);
        munmap(controllerStatus, sizeof(ControllerStatus));
        close(shmFd);
        shm_unlink(SHM_NAME);
        return -1;
    }

    // Initialize the mutex
    if (pthread_mutex_init(controllerMutex, &attr) != 0) {
        perror("pthread_mutex_init failed");
        pthread_mutexattr_destroy(&attr);
        munmap(controllerMutex, sizeof(pthread_mutex_t));
        munmap(controllerStatus, sizeof(ControllerStatus));
        close(shmFd);
        shm_unlink(SHM_NAME);
        return -1;
    }

    pthread_mutexattr_destroy(&attr);

    // Only initialize shared memory if this is the first process
    if (sb.st_size == 0) {
        controllerStatus->controllerActive = 0;
        memset(controllerStatus->controllerId, 0, MAX_USER_ID_LEN);
    }

    return 0;
}

// Function to cleanup shared memory and mutex
void cleanup_shared_memory() {
    if (controllerMutex != NULL) {
        pthread_mutex_destroy(controllerMutex);
        munmap(controllerMutex, sizeof(pthread_mutex_t));
    }
    if (controllerStatus != NULL) {
        munmap(controllerStatus, sizeof(ControllerStatus));
    }
    if (shmFd != -1) {
        close(shmFd);
        shm_unlink(SHM_NAME);
    }
}

// Function to handle controller takeover
int handle_controller_takeover(FILE *log_file) {
    // Try to acquire mutex
    if (pthread_mutex_lock(controllerMutex) != 0) {
        perror("Failed to acquire mutex");
        return 0;
    }

    // Check if controller is already active
    if (controllerStatus->controllerActive) {
        printf("Another client has already become the controller.\n");
        log_message(log_file, user_id, "Another client became controller, remaining as client");
        pthread_mutex_unlock(controllerMutex);
        return 0;
    }

    // Prompt user
    printf("\nController is down. Would you like to become the new controller?\n");
    printf("Enter a number between 0-30 to accept, any other input to decline: ");
    
    char input[MAX_MSG_LEN];
    if (fgets(input, sizeof(input), stdin) != NULL) {
        input[strcspn(input, "\n")] = 0;  // Remove newline
        
        int new_interval;
        if (sscanf(input, "%d", &new_interval) == 1) {
            if (new_interval >= 0 && new_interval <= 30) {
                // Double check controller status while holding mutex
                if (controllerStatus->controllerActive) {
                    printf("Another client has already become the controller.\n");
                    log_message(log_file, user_id, "Another client became controller while waiting for input");
                    pthread_mutex_unlock(controllerMutex);
                    return 0;
                }

                // Set controller status atomically
                controllerStatus->controllerActive = 1;
                strncpy(controllerStatus->controllerId, user_id, MAX_USER_ID_LEN - 1);
                controllerStatus->controllerId[MAX_USER_ID_LEN - 1] = '\0';
                
                // Become the new controller
                is_controller = 1;
                heartbeat_interval = new_interval;
                log_message(log_file, user_id, "Assuming controller role with interval %d", new_interval);
                
                // Release mutex before sending messages
                pthread_mutex_unlock(controllerMutex);
                
                // Send initial interval command
                send_interval_command(new_interval, log_file);
                return 1;
            }
        }
        printf("Invalid input. Remaining as client.\n");
        log_message(log_file, user_id, "Declined controller role");
    }
    
    pthread_mutex_unlock(controllerMutex);
    return 0;
}

// Function to receive and process messages
void receive_messages(int sockfd, FILE *log_file) {
    char buffer[MAX_MSG_LEN];
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);

    // receive message
    ssize_t num_bytes = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, 
                                (struct sockaddr *)&sender_addr, &sender_len);
    if (num_bytes < 0) {
        perror("recvfrom");
        return;
    }

    buffer[num_bytes] = '\0';  // Null terminate the received message
    char *sender_ip = inet_ntoa(sender_addr.sin_addr);
    int sender_port = ntohs(sender_addr.sin_port);

    // Extract sender ID from message if possible
    char message_sender[MAX_USER_ID_LEN] = {0};
    if (strncmp(buffer, "HEARTBEAT from", 13) == 0) {
        sscanf(buffer, "HEARTBEAT from %s", message_sender);
    } else if (strncmp(buffer, "BYE", 3) == 0) {
        sscanf(buffer, "BYE from %s", message_sender);
    }

    // Ignore messages from self (either by IP or by user ID in message)
    if (strcmp(sender_ip, user_id) == 0 || 
        (strlen(message_sender) > 0 && strcmp(message_sender, user_id) == 0)) {
        return;
    }

    // Process message based on role
    if (is_controller) {
        // Controller processes client heartbeats
        if (strncmp(buffer, "HEARTBEAT from", 13) == 0) {
            char client_id[MAX_USER_ID_LEN];
            if (sscanf(buffer, "HEARTBEAT from %s", client_id) == 1) {
                log_message(log_file, user_id, "Received heartbeat from client %s (IP: %s, Port: %d)", 
                           client_id, sender_ip, sender_port);
            }
        } else if (strncmp(buffer, "SET_INTERVAL", 11) == 0) {
            // Ignore SET_INTERVAL messages as controller - they must be from ourselves
            return;
        } else {
            // Log uninterpretable message
            log_message(log_file, user_id, "Received uninterpretable message from %s:%d: %s", 
                       sender_ip, sender_port, buffer);
        }
    } else {
        // Client processes controller commands
        if (strncmp(buffer, "SET_INTERVAL", 11) == 0) {
            int new_interval;
            if (sscanf(buffer, "SET_INTERVAL %d", &new_interval) == 1) {
                log_message(log_file, user_id, "Received SET_INTERVAL command from controller (IP: %s, Port: %d) with value %d", 
                           sender_ip, sender_port, new_interval);
                heartbeat_interval = new_interval;
            }
        }
        else if (strncmp(buffer, "BYE", 3) == 0) {
            log_message(log_file, user_id, "Received BYE message from controller (IP: %s, Port: %d)", 
                       sender_ip, sender_port);
            handle_controller_takeover(log_file);
        }
        else if (strncmp(buffer, "CONTROLLER_DOWN", 14) == 0) {
            log_message(log_file, user_id, "Received CONTROLLER_DOWN command from controller (IP: %s, Port: %d)", 
                       sender_ip, sender_port);
            handle_controller_takeover(log_file);
        }
        else if (strncmp(buffer, "HEARTBEAT from", 13) == 0) {
            char client_id[MAX_USER_ID_LEN];
            if (sscanf(buffer, "HEARTBEAT from %s", client_id) == 1) {
                log_message(log_file, user_id, "Received heartbeat from client %s (IP: %s, Port: %d)", 
                           client_id, sender_ip, sender_port);
            }
        }
        else {
            // Log uninterpretable message
            log_message(log_file, user_id, "Received uninterpretable message from %s:%d: %s", 
                       sender_ip, sender_port, buffer);
        }
    }
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

// Function to handle controller shutdown
void handle_controller_shutdown(FILE *log_file, int is_abort) {
    if (is_controller) {
        // Release controller status atomically
        if (pthread_mutex_lock(controllerMutex) == 0) {
            if (strcmp(controllerStatus->controllerId, user_id) == 0) {
                controllerStatus->controllerActive = 0;
                memset(controllerStatus->controllerId, 0, MAX_USER_ID_LEN);
            }
            pthread_mutex_unlock(controllerMutex);
        }

        if (is_abort) {
            // For abort, try to send CONTROLLER_DOWN quickly
            send_controller_down(log_file);
            log_message(log_file, user_id, "Controller aborting");
        } else {
            // For normal exit, send BYE and CONTROLLER_DOWN
            log_message(log_file, user_id, "Controller shutting down");
            send_controller_down(log_file);
            send_multicast_message("BYE");
        }
    }
    
    // Close resources
    if (log_file != NULL) {
        fclose(log_file);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
    cleanup_shared_memory();
}

// Function to handle controller input
void handle_controller_input(FILE *log_file) {
    char input[MAX_MSG_LEN];
    if (fgets(input, sizeof(input), stdin) != NULL) {
        input[strcspn(input, "\n")] = 0;  // Remove newline

        if (strcmp(input, "exit") == 0) {
            log_message(log_file, user_id, "User entered exit command");
            handle_controller_shutdown(log_file, 0);
            exit(EXIT_SUCCESS);
        }
        else if (strcmp(input, "abort") == 0) {
            log_message(log_file, user_id, "User entered abort command");
            handle_controller_shutdown(log_file, 1);
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

// Function to check for controller failure
void check_controller_status(FILE *log_file) {
    if (!is_controller && strlen(current_controller_id) > 0) {
        time_t current_time = time(NULL);
        if (current_time - last_controller_heartbeat > heartbeat_interval * MISSED_HEARTBEAT_THRESHOLD) {
            missed_heartbeats++;
            printf("\nWarning: Missed %d heartbeats from controller %s\n", 
                   missed_heartbeats, current_controller_id);
            
            if (missed_heartbeats >= MISSED_HEARTBEAT_THRESHOLD) {
                printf("\nController %s appears to be down. Would you like to become the new controller?\n", 
                       current_controller_id);
                printf("Enter a number between 0-30 to accept, any other input to decline: ");
                
                char input[MAX_MSG_LEN];
                if (fgets(input, sizeof(input), stdin) != NULL) {
                    input[strcspn(input, "\n")] = 0;  // Remove newline
                    
                    int new_interval;
                    if (sscanf(input, "%d", &new_interval) == 1) {
                        if (new_interval >= 0 && new_interval <= 30) {
                            log_message(log_file, user_id, "Becoming new controller with interval %d", new_interval);
                            is_controller = 1;
                            heartbeat_interval = new_interval;
                            memset(current_controller_id, 0, MAX_USER_ID_LEN);
                            send_interval_command(new_interval, log_file);
                        } else {
                            printf("Invalid interval. Remaining as client.\n");
                            log_message(log_file, user_id, "Declined controller role due to invalid interval");
                        }
                    } else {
                        printf("Invalid input. Remaining as client.\n");
                        log_message(log_file, user_id, "Declined controller role");
                    }
                }
                missed_heartbeats = 0;  // Reset counter after prompt
            }
        }
    }
}


// Add signal handler for clean shutdown
void signal_handler(int signum) {
    if (is_controller) {
        FILE *log_file = fopen("heartbeat_app_controller.log", "a");
        if (log_file != NULL) {
            handle_controller_shutdown(log_file, 0);
        }
    }
    exit(signum);
}

int main(int argc, char *argv[]) {
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (parse_arguments(argc, argv) != 0) {
        return EXIT_FAILURE;
    }

    // Initialize controller tracking variables
    memset(current_controller_id, 0, MAX_USER_ID_LEN);
    last_controller_heartbeat = 0;
    missed_heartbeats = 0;

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

    // Initialize shared memory and mutex
    if (init_shared_memory() != 0) {
        fprintf(stderr, "Failed to initialize shared memory\n");
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
            // Controller mode
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
                handle_controller_shutdown(log_file, 0);
                break;
            }

            // Handle socket input
            if (FD_ISSET(sockfd, &read_fds)) {
                receive_messages(sockfd, log_file);
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
        } else {
            // Client mode
            fd_set read_fds;
            struct timeval tv;
            
            FD_ZERO(&read_fds);
            FD_SET(sockfd, &read_fds);
            FD_SET(STDIN_FILENO, &read_fds);  // Add stdin to check for user input
            
            // Set timeout for select
            tv.tv_sec = 0;  // Don't block
            tv.tv_usec = 100000;  // 100ms timeout
            
            if (select(sockfd + 1, &read_fds, NULL, NULL, &tv) > 0) {
                // Handle socket input
                if (FD_ISSET(sockfd, &read_fds)) {
                    receive_messages(sockfd, log_file);
                }
                
                // Handle user input
                if (FD_ISSET(STDIN_FILENO, &read_fds)) {
                    char input[MAX_MSG_LEN];
                    if (fgets(input, sizeof(input), stdin) != NULL) {
                        input[strcspn(input, "\n")] = 0;  // Remove newline
                        
                        if (strcmp(input, "exit") == 0) {
                            log_message(log_file, user_id, "User entered exit command");
                            // Send BYE message
                            send_multicast_message("BYE");
                            // Close resources
                            fclose(log_file);
                            close(sockfd);
                            cleanup_shared_memory();
                            exit(EXIT_SUCCESS);
                        }
                        else if (strcmp(input, "abort") == 0) {
                            log_message(log_file, user_id, "User entered abort command");
                            fclose(log_file);
                            close(sockfd);
                            cleanup_shared_memory();
                            abort();
                        }
                        else {
                            // Reject any other input
                            printf("Invalid input. Only 'exit' and 'abort' commands are accepted.\n");
                        }
                    }
                }
            }
            
            // Send heartbeat with random delay
            if (heartbeat_interval > 0) {
                // Add random delay between 0 and 0.5 seconds
                usleep((rand() % 500000) + 1);
                send_heartbeat(log_file);
                sleep(heartbeat_interval);
            }
        }
    }

    // Clean shutdown if we exit the main loop
    if (is_controller) {
        handle_controller_shutdown(log_file, 0);
    }
    cleanup_shared_memory();
    return EXIT_SUCCESS;
}