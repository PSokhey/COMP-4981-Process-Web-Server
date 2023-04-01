#include <dc_c/dc_stdio.h>
#include <dc_c/dc_stdlib.h>
#include <dc_c/dc_string.h>
#include <dc_posix/arpa/dc_inet.h>
#include <dc_posix/dc_dlfcn.h>
#include <dc_posix/dc_poll.h>
#include <dc_posix/dc_semaphore.h>
#include <dc_posix/dc_signal.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/dc_unistd.h>
#include <dc_posix/sys/dc_select.h>
#include <dc_posix/sys/dc_socket.h>
#include <dc_posix/sys/dc_wait.h>
#include <dc_unix/dc_getopt.h>
#include <dc_util/networking.h>
#include <dc_util/system.h>
#include <dc_util/types.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>


typedef ssize_t (*read_message_func)(const struct dc_env *env, struct dc_error *err, uint8_t **raw_data, int client_socket);
typedef size_t (*process_message_func)(const struct dc_env *env, struct dc_error *err, const uint8_t *raw_data, uint8_t **processed_data, ssize_t count);
typedef void (*send_message_func)(const struct dc_env *env, struct dc_error *err, uint8_t *buffer, size_t count, int client_socket, bool *closed);

// Settings information passed to the server.
struct settings
{
    char *library_path; // Path to the library containing the message handler.
    char *interface; // Interface to bind to.
    char *address; // Address to bind to.
    uint16_t port; // Port to bind to.
    uint16_t backlog; // Number of connections to queue.
    uint8_t jobs; // Number of worker processes to spawn.
    bool verbose_server; // Whether to print verbose server information.
    bool verbose_handler; // Whether to print verbose handler information.
    bool debug_server; // Whether to print debug server information.
    bool debug_handler; // Whether to print debug handler information.
};

// Information about the server.
// The Parent process accepts connections on domain socket and passes them to the worker processes.
struct server_info
{
    sem_t *domain_sem; // Semaphore used to synchronize access to the domain socket.
    int domain_socket; // Domain socket used to communicate with the worker to pass client sockets.
    int pipe_fd; // Pipe used to communicate with the worker processes to send commands.
    int num_workers; // Number of worker processes.
    pid_t *workers; // Array of worker process ids.
    int listening_socket; // Socket used to accept connections.
    int num_fds; // Number of file descriptors in the poll_fds array.
    struct pollfd *poll_fds; // Array of file descriptors to poll.
};

// for handling incoming messages
struct message_handler
{
    read_message_func reader; // Function used to read a message from a socket.
    process_message_func processor; // Function used to process a message.
    send_message_func sender; // Function used to send a message to a socket.
};


// Information about a worker process.
struct worker_info
{
    sem_t *select_sem; // Semaphore used to synchronize access to the select call.
    sem_t *domain_sem; // Semaphore used to synchronize access to the domain socket.
    int domain_socket; // Domain socket used to communicate with the parent to pass client sockets.
    int pipe_fd; // Pipe used to communicate with the parent process to receive commands.
    struct message_handler message_handler;
};

// Information about a client connection.
struct revive_message
{
    int fd; // File descriptor of the client socket.
    bool closed; // Whether the client socket has been closed.
};


static void setup_default_settings(const struct dc_env *env, struct dc_error *err, struct settings *default_settings);
static void copy_settings(const struct dc_env *env, struct dc_error *err, struct settings *settings, const struct settings *default_settings);
static void print_settings(const struct dc_env *env, const struct settings *settings);
static void destroy_settings(const struct dc_env *env, struct settings *settings);
static bool parse_args(const struct dc_env *env, struct dc_error *err, int argc, char **argv, struct settings *settings);
static const char *check_settings(const struct dc_env *env, const struct settings *settings);
static void usage(const struct dc_env *env, const char *program_name, const struct settings *default_settings, const char *message);
static void sigint_handler(int signal);
static void setup_message_handler(const struct dc_env *env, struct dc_error *err, struct message_handler *message_handler, void *library);
static bool create_workers(struct dc_env *env, struct dc_error *err, const struct settings *settings, pid_t *workers, sem_t *select_sem, sem_t *domain_sem, const int domain_sockets[2], const int pipe_fds[2]);
static void initialize_server(const struct dc_env *env, struct dc_error *err, struct server_info *server,  const struct settings *settings, sem_t *domain_sem, int domain_socket, int pipe_fd, pid_t *workers);
static void destroy_server(const struct dc_env *env, struct dc_error *err, struct server_info *server);
static void run_server(const struct dc_env *env, struct dc_error *err, struct server_info *server, const struct settings *settings);
static void server_loop(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server);
static bool handle_change(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server, struct pollfd *poll_fd);
static void accept_connection(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server);
static void write_socket_to_domain_socket(const struct dc_env *env, struct dc_error *err, const struct settings *settings, const struct server_info *server, int client_socket);
static void revive_socket(const struct dc_env *env, struct dc_error *err, const struct settings *settings, const struct server_info *server, struct revive_message *message);
static void close_connection(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server, int client_socket);
static void wait_for_workers(const struct dc_env *env, struct dc_error *err, struct server_info *server);
static void worker_process(struct dc_env *env, struct dc_error *err, struct worker_info *worker, const struct settings *settings);
static bool extract_message_parameters(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, int *client_socket, int *value);
static void process_message(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, const struct settings *settings);
static void send_revive(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, int client_socket, int fd, bool closed);
static void print_fd(const struct dc_env *env, const char *message, int fd, bool display);
static void print_socket(const struct dc_env *env, struct dc_error *err, const char *message, int socket, bool display);

// Default settings.
static const int DEFAULT_N_PROCESSES = 2; // Default number of worker processes.
static const int DEFAULT_PORT = 8080; // Default port to listen on.
static const int DEFAULT_BACKLOG = SOMAXCONN; // Default backlog for the listening socket.
static const char * const READ_MESSAGE_FUNC = "read_message_handler"; // Default function used to read a message from a socket.
static const char * const PROCESS_MESSAGE_FUNC = "process_message_handler"; // Default function used to process a message.
static const char * const SEND_MESSAGE_FUNC = "send_message_handler"; // Default function used to send a message to a socket.
static volatile sig_atomic_t done = 0;     // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

// To Drive the program.
int main(int argc, char *argv[])
{
    struct dc_error *err;
    struct dc_env *env;
    bool should_exit;
    struct settings *default_settings;
    struct settings settings;
    const char *error_message;

    // Initialization of error and environment handling.
    err = dc_error_create(false); // initialize error handling.
    env = dc_env_create(err, true, NULL); // initialize environment.

    // Initialize default settings.
    default_settings = dc_malloc(env, err, sizeof(*default_settings)); // allocate memory for default settings.
    setup_default_settings(env, err, default_settings); // set default settings.

    // Initialize settings to run server.
    // Copy default settings to settings.
    // Parse user settings.
    dc_memset(env, &settings, 0, sizeof(settings)); // initialize settings to 0.
    copy_settings(env, err, &settings, default_settings); // copy default settings to settings.
    should_exit = parse_args(env, err, argc, argv, &settings); // parse command line arguments, flag for if valid commands.

    // Check if settings are valid and if error message, set flag to exit as true if an error.
    if(!(should_exit))
    {
        error_message = check_settings(env, &settings);

        if(error_message != NULL)
        {
            should_exit = true;
        }
    }

    // else continue with no error message.
    else
    {
        error_message = NULL;
    }

    // checks if flagged for exit due to error or help parsed, print help and clean resources.
    if(should_exit)
    {
        usage(env, argv[0], default_settings, error_message); // print optional commands.
        destroy_settings(env, default_settings); // destroy settings.
        dc_free(env, default_settings); // free memory for default settings.
    }

    // else, run the server with settings now set.
    else
    {
        sem_t *select_sem;  // select semaphore for interprocess comminication.*
        sem_t *domain_sem; // domain socket semaphore for server-worker communication.*
        int domain_sockets[2]; // domain socket for reading and writing.*
        int pipe_fds[2]; // pipe for reading and writing.*
        pid_t *workers; // array of worker processes.
        bool is_server; // flag for if server, else worker.
        pid_t pid;
        char domain_sem_name[100];  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        char select_sem_name[100];  // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

        // if to print debug messages.
        if(settings.debug_server)
        {
            dc_env_set_tracer(env, dc_env_default_tracer);
        }

        // destroy default settings because already copied to current settings.
        destroy_settings(env, default_settings);
        dc_free(env, default_settings);

        // Set the interprocess communication.
        socketpair(AF_UNIX, SOCK_DGRAM, 0, domain_sockets); // set domain socket.
        dc_pipe(env, err, pipe_fds); // set pipe.

        // Print server settings and main server process id.
        printf("Starting server (%d) on %s:%d\n", getpid(), settings.address, settings.port);
        print_settings(env, &settings);

        // Set up the semaphores to synchronize the server and workers.
        workers = NULL; // worker array set to null.
        pid = getpid(); // get main server process id.
        // creates a name for the domain semaphore.
        sprintf(domain_sem_name, "/sem-%d-domain", pid);    // NOLINT(cert-err33-c)
        // creates a name for the select semaphore.
        sprintf(select_sem_name, "/sem-%d-select", pid);    // NOLINT(cert-err33-c)
        // open the select semaphore.
        select_sem = sem_open(select_sem_name, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, 1);
        // open the domain semaphore.
        domain_sem = sem_open(domain_sem_name, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, 1);
        // allocates memory for the worker array.
        workers = (pid_t *)dc_malloc(env, err, settings.jobs * sizeof(pid_t));
        // create the workers with the settings, worker array, semaphores, domain sockets, and pipe.
        is_server = create_workers(env, err, &settings, workers, select_sem, domain_sem, domain_sockets, pipe_fds);

        // To be only done by the server.
        if(is_server)
        {
            struct sigaction act; // signal action for signal interrupt.
            struct server_info server; // server information.

            // Set up the signal handler.
            act.sa_handler = sigint_handler;
            dc_sigemptyset(env, err, &act.sa_mask);
            act.sa_flags = 0;
            dc_sigaction(env, err, SIGINT, &act, NULL);

            // Adjust IPC for the server (not workers).
            dc_close(env, err, domain_sockets[0]); // close the domain socket for reading, can only write.
            dc_close(env, err, pipe_fds[1]); // close the pipe for writing, can only read.

            // Initialize and from here run the server.
            // Allocate memory for the server information and zero it out.
            dc_memset(env, &server, 0, sizeof(server));
            // Initialize the server with the settings, semaphores, domain sockets (write), and pipe (read).
            initialize_server(env, err, &server, &settings, domain_sem, domain_sockets[1], pipe_fds[0], workers);
            // Run and loop server till it is time to exit.
            run_server(env, err, &server, &settings);

            // From here the server has stopped running and is about to exit.
            destroy_server(env, err, &server); // clean semaphore and socket resources.
        }

        // Close and unlink the semaphores.
        sem_close(domain_sem); // close the domain semaphore.
        sem_close(select_sem); // close the select semaphore.

        // To be only done by the server.
        if(is_server)
        {
            sem_unlink(domain_sem_name); // removed named domain semaphore.
            sem_unlink(select_sem_name); // removed named select semaphore.
        }
    }

    // Clean up all remaining resources before exiting.
    destroy_settings(env, &settings);
    printf("Exiting %d\n", getpid()); // print exiting process id, worker or server.
    free(env);
    dc_error_reset(err);
    free(err);

    return EXIT_SUCCESS;
}

// Set the default settings if not set by the user.
static void setup_default_settings(const struct dc_env *env, struct dc_error *err, struct settings *default_settings)
{
    DC_TRACE(env);
    default_settings->library_path     = NULL;
    default_settings->interface        = dc_get_default_interface(env, err, AF_INET);
    default_settings->address          = dc_get_ip_addresses_by_interface(env, err, default_settings->interface, AF_INET);
    default_settings->port             = DEFAULT_PORT;
    default_settings->backlog          = DEFAULT_BACKLOG;
    default_settings->jobs             = dc_get_number_of_processors(env, err, DEFAULT_N_PROCESSES);
    default_settings->verbose_server   = false;
    default_settings->verbose_handler  = false;
    default_settings->debug_server     = false;
    default_settings->debug_handler    = false;
}

// Copy the default settings to the current settings.
static void copy_settings(const struct dc_env *env, struct dc_error *err, struct settings *settings, const struct settings *default_settings)
{
    DC_TRACE(env);
    settings->interface        = dc_strdup(env, err, default_settings->interface);
    settings->address          = dc_strdup(env, err, default_settings->address);
    settings->port             = default_settings->port;
    settings->backlog          = default_settings->backlog;
    settings->jobs             = default_settings->jobs;
    settings->verbose_server   = default_settings->verbose_server;
    settings->verbose_handler  = default_settings->verbose_handler;
    settings->debug_server     = default_settings->debug_server;
    settings->debug_handler    = default_settings->debug_handler;
}

// Display the current settings state.
static void print_settings(const struct dc_env *env, const struct settings *settings)
{
    DC_TRACE(env);
    // NOLINTBEGIN(cert-err33-c)
    fprintf(stderr, "\tLibrary:            %s\n",  settings->library_path);
    fprintf(stderr, "\tNetwork interface:  %s\n",  settings->interface);
    fprintf(stderr, "\tIP address:         %s\n",  settings->address);
    fprintf(stderr, "\tPort number:        %d\n",  settings->port);
    fprintf(stderr, "\tBacklog size:       %d\n",  settings->backlog);
    fprintf(stderr, "\tNumber of handlers: %d\n",  settings->jobs);
    fprintf(stderr, "\tVerbose server:     %s\n",  settings->verbose_server == true ? "on" : "off");
    fprintf(stderr, "\tVerbose handler:    %s\n",  settings->verbose_handler == true ? "on" : "off");
    fprintf(stderr, "\tVerbose server:     %s\n",  settings->debug_server == true ? "on" : "off");
    fprintf(stderr, "\tVerbose handler:    %s\n",  settings->debug_handler == true ? "on" : "off");
    // NOLINTEND(cert-err33-c)
}

// Clean up of the setting resources taking memory.
static void destroy_settings(const struct dc_env *env, struct settings *settings)
{
    DC_TRACE(env);

    if(settings->library_path)
    {
        dc_free(env, settings->library_path);
    }

    if(settings->interface)
    {
        dc_free(env, settings->interface);
    }

    if(settings->address)
    {
        dc_free(env, settings->address);
    }
}

// Parse the command line arguments and set the settings.
static bool parse_args(const struct dc_env *env, struct dc_error *err, int argc, char **argv, struct settings *settings)
{
    static const int base = 10;
    static struct option long_options[] =
            {
                    {"library_path", required_argument, 0, 'l'},
                    {"interface", required_argument, 0, 'i'},
                    {"address", required_argument, 0, 'a'},
                    {"port", required_argument, 0, 'p'},
                    {"backlog", required_argument, 0, 'b'},
                    {"jobs", required_argument, 0, 'j'},
                    {"buffer-size", required_argument, 0, 's'},
                    {"timeout-seconds", required_argument, 0, 'T'},
                    {"timeout-nseconds", required_argument, 0, 't'},
                    {"verbose-server", no_argument, 0, 'v'},
                    {"verbose-handler", no_argument, 0, 'V'},
                    {"debug-server", no_argument, 0, 'd'},
                    {"debug-handler", no_argument, 0, 'D'},
                    {"help", no_argument, 0, 'h'},
                    {0, 0, 0, 0}
            };
    int opt;
    int option_index;
    bool should_exit;

    DC_TRACE(env);
    option_index = 0;
    should_exit = false;

    // While there are options to parse, set the settings.
    while((opt = dc_getopt_long(env, argc, argv, "l:i:a:p:b:j:vVdDh", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
            case 'l':
                settings->library_path = dc_strdup(env, err, optarg);
                break;
            case 'i':
                settings->interface = dc_strdup(env, err, optarg);
                break;
            case 'a':
                settings->address = dc_strdup(env, err, optarg);
                break;
            case 'p':
                settings->port = dc_uint16_from_str(env, err, optarg, base);
                break;
            case 'b':
                settings->backlog = dc_uint16_from_str(env, err, optarg, base);
                break;
            case 'j':
                settings->jobs = dc_uint8_from_str(env, err, optarg, base);
                break;
            case 'v':
                settings->verbose_server = true;
                break;
            case 'V':
                settings->verbose_handler = true;
                break;
            case 'd':
                settings->debug_server = true;
                break;
            case 'D':
                settings->debug_handler = true;
                break;
            case 'h':
                should_exit = true;
            default:
                break;
        }
    }

    return should_exit;
}

// Check the settings for errors, and return a message if there is an error.
static const char *check_settings(const struct dc_env *env, const struct settings *settings)
{
    const char *message;

    DC_TRACE(env);

    if(settings->library_path == NULL)
    {
        message = "library_path argument missing";
    }
    else
    {
        message = NULL;
    }

    return message;
}

// Print the usage of the program to the user if error or requested help.
static void usage(const struct dc_env *env, const char *program_name, const struct settings *default_settings, const char *message)
{
    DC_TRACE(env);

    // NOLINTBEGIN(cert-err33-c)
    if(message != NULL)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s [options]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "\t-l, --library_path          Library (default: %s)\n", default_settings->library_path);
    fprintf(stderr, "\t-i, --interface        Network interface (default: %s)\n", default_settings->interface);
    fprintf(stderr, "\t-a, --address          IP address (default: %s)\n", default_settings->address);
    fprintf(stderr, "\t-p, --port             Port number (default: %d)\n", default_settings->port);
    fprintf(stderr, "\t-b, --backlog          Backlog size (default: %d)\n", default_settings->backlog);
    fprintf(stderr, "\t-j, --jobs             Number of handlers (default: %d)\n", default_settings->jobs);
    fprintf(stderr, "\t-v, --verbose-server   Verbose server (default: %s)\n", default_settings->verbose_server == true ? "on" : "off");
    fprintf(stderr, "\t-V, --verbose-handler  Verbose handler (default: %s)\n", default_settings->verbose_handler == true ? "on" : "off");
    fprintf(stderr, "\t-v, --debug-server     Debug server (default: %s)\n", default_settings->debug_server == true ? "on" : "off");
    fprintf(stderr, "\t-V, --debug-handler    Debug handler (default: %s)\n", default_settings->debug_handler == true ? "on" : "off");
    fprintf(stderr, "\t-h, --help             Display this help message\n");
    // NOLINTEND(cert-err33-c)
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
// Signal handler for SIGINT, this code should remain unchanged.
// Many parts of the program rely on this to know if the program is done or not.
static void sigint_handler(int signal)
{
    done = true;
}
#pragma GCC diagnostic pop

// Linking passed in library to function pointers, this code should remain unchanged.
static void setup_message_handler(const struct dc_env *env, struct dc_error *err, struct message_handler *message_handler, void *library)
{
    read_message_func    read_func;
    process_message_func process_func;
    send_message_func    send_func;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    read_func = (read_message_func)dc_dlsym(env, err, library, READ_MESSAGE_FUNC);
#pragma GCC diagnostic pop

    if(dc_error_has_no_error(err))
    {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
        process_func = (process_message_func) dc_dlsym(env, err, library, PROCESS_MESSAGE_FUNC);
#pragma GCC diagnostic pop

        if(dc_error_has_no_error(err))
        {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
            send_func = (send_message_func)dc_dlsym(env, err, library, SEND_MESSAGE_FUNC);
#pragma GCC diagnostic pop

            if(dc_error_has_no_error(err))
            {
                message_handler->reader = read_func;
                message_handler->processor = process_func;
                message_handler->sender = send_func;
            }
        }
    }
}

// Create the worker processes, return is only true for server and false for worker processes.
static bool create_workers(struct dc_env *env, struct dc_error *err, const struct settings *settings, pid_t *workers, sem_t *select_sem, sem_t *domain_sem, const int domain_sockets[2], const int pipe_fds[2])
{
    DC_TRACE(env);

    // Loop for as many worker child processes needed to be created.
    for(int i = 0; i < settings->jobs; i++)
    {
        pid_t pid; // Process ID to differentiate between server and worker processes.

        // Fork the process to create a child process.
        pid = dc_fork(env, err);

        // To only apply to worker child processes.
        // Setting of the worker process information.
        if(pid == 0)
        {
            struct sigaction act; // Signal action for SIGINT.
            struct worker_info worker; // Worker information.
            void *library; // Library to be linked to.

            // Set the signal handler for SIGINT.
            act.sa_handler = sigint_handler;
            dc_sigemptyset(env, err, &act.sa_mask);
            act.sa_flags = 0;
            dc_sigaction(env, err, SIGINT, &act, NULL);
            dc_free(env, workers);

            // Adjust the IPC for the workers (not server)
            dc_close(env, err, domain_sockets[1]); // Close write end of the domain socket, can only read.
            dc_close(env, err, pipe_fds[0]); // Close read end of the pipe, can only write.

            // Access the library parsed in.
            library = dc_dlopen(env, err, settings->library_path, RTLD_LAZY);

            // If no errors, finish rest of worker process setup.
            if(dc_error_has_no_error(err))
            {
                // Set up the message handler for the worker process.
                // Allocate memory and zero out the message handler for the worker process.
                dc_memset(env, &worker.message_handler, 0, sizeof(worker.message_handler));
                // Link the library to the message handler.
                setup_message_handler(env, err, &worker.message_handler, library);

                // Set the semaphore and IPC for worker process.
                worker.select_sem = select_sem; // Select semaphore.
                worker.domain_sem = domain_sem; // Domain semaphore.
                worker.domain_socket = domain_sockets[0]; // domain socket, can only read.
                worker.pipe_fd = pipe_fds[1]; // pipe, can only write.

                // Run the worker process.
                worker_process(env, err, &worker, settings);
                // Close the library.
                dc_dlclose(env, err, library);
            }

            // Return false to indicate that this is a worker process.
            return false;
        }

        // Add to the worker process array.
        workers[i] = pid;
    }

    // Return true to indicate that this is the server process.
    return true;
}

// Initialize the server settings for IPC and network communication.
static void initialize_server(const struct dc_env *env, struct dc_error *err, struct server_info *server,  const struct settings *settings, sem_t *domain_sem, int domain_socket, int pipe_fd, pid_t *workers)
{
    static int optval = 1;
    struct sockaddr_in server_address;

    DC_TRACE(env);

    // Server setup for IPC and listening socket.
    server->domain_sem = domain_sem;
    server->domain_socket = domain_socket;
    server->pipe_fd = pipe_fd;
    server->num_workers = settings->jobs;
    server->workers = workers;
    server->listening_socket = socket(AF_INET, SOCK_STREAM, 0); // Socket for incoming network connections.

    // Network communication setup.
    dc_memset(env, &server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = dc_inet_addr(env, err, settings->address);
    server_address.sin_port = dc_htons(env, settings->port);
    dc_setsockopt(env, err, server->listening_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    dc_bind(env, err, server->listening_socket, (struct sockaddr *)&server_address, sizeof(server_address));
    dc_listen(env, err, server->listening_socket, settings->backlog);

    // Allocate memory for polling.
    server->poll_fds = (struct pollfd *)dc_malloc(env, err, sizeof(struct pollfd) * 2);

    // For changes in network socket for incoming connections, listening for input.
    server->poll_fds[0].fd = server->listening_socket; // File descriptor for the listening socket.
    server->poll_fds[0].events = POLLIN; // Poll for input, there is data to be read.
    // For changes in pipe for worker processes, listening for input.
    server->poll_fds[1].fd = server->pipe_fd; // File descriptor for the pipe.
    server->poll_fds[1].events = POLLIN; // Poll for input, there is data to be read.
    server->num_fds = 2;
}

// Destroy all worker processes and poll file descriptors for the server.
static void destroy_server(const struct dc_env *env, struct dc_error *err, struct server_info *server)
{
    if(server->poll_fds)
    {
        dc_free(env, server->poll_fds);
    }

    if(server->workers)
    {
        dc_free(env, server->workers);
    }

    dc_close(env, err, server->domain_socket);
    dc_close(env, err, server->pipe_fd);
}

// Main function to run the server once all setup is finished.
static void run_server(const struct dc_env *env, struct dc_error *err, struct server_info *server, const struct settings *settings)
{
    DC_TRACE(env);
    // Run the server loop until done.
    server_loop(env, err, settings, server);

    /*
    for(int i = 0; i < server->num_workers; i++)
    {
        kill(server->workers[i], SIGINT);
    }
    */

    // Wait for all worker processes to finish once server is done.
    wait_for_workers(env, err, server);
}

// Server loop to keep polling until error or SIGINT.
static void server_loop(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server)
{
    DC_TRACE(env);

    // run endlessly until error or SIGINT.
    // 'done' is a necessary global variable, do NOT remove.
    while(!done)
    {
        int poll_result;

        // Poll for changes in the file descriptors, data to be read.
        poll_result = dc_poll(env, err, server->poll_fds, server->num_fds, -1);

        // End loop on an error when listening.
        if(poll_result < 0)
        {
            break;
        }

        // No changes occur, return to the beginning of the loop.
        if(poll_result == 0)
        {
            continue;
        }

        // the increment only happens if the connection isn't closed.
        // if it is closed everything moves down one spot.
        for(int i = 0; i < server->num_fds; i++)
        {
            // dc_poll tells there was a change, now check to see which polling fd had the change.
            struct pollfd *poll_fd; // Polling file descriptor to check.

            // First fd is for incoming connections, second for pipe data from workers.
            poll_fd = &server->poll_fds[i];

            // If there was a change in the file descriptor, handle the change.
            if(poll_fd->revents != 0)
            {
                handle_change(env, err, settings, server, poll_fd);
            }
        }

        // if error when checking polling file descriptors, end loop.
        // 'done' is a necessary global variable, do NOT remove.
        if(dc_error_has_error(err))
        {
            done = true;
        }
    }
}

// Handle changes in the polling file descriptors
//TODO: THIS IS WHERE SERVER PROCESSES FOR CONNECTIONS AND WORKER IPC, NEED TO ADD CHAT PROTOCOL BRANCHING HERE.
static bool handle_change(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server, struct pollfd *poll_fd)
{
    int fd;
    short revents;
    int close_fd;

    DC_TRACE(env);
    fd = poll_fd->fd;
    revents = poll_fd->revents;
    close_fd = -1;

    // connection closed by client and mark for closing.
    if((unsigned int)revents & (unsigned int)POLLHUP)
    {
        if(fd != server->listening_socket && fd != server->pipe_fd)
        {
            close_fd = fd;
        }
    }

    // There is data to be read in the listening socket or pipe.
    else if((unsigned int)revents & (unsigned int)POLLIN)
    {
        // If the file descriptor is the listening socket, accept the connection.
        if(fd == server->listening_socket)
        {
            accept_connection(env, err, settings, server);
        }

        // If the file descriptor is the pipe, read the data sent from the worker processes.
        // TODO: ADD CODE TO HANDLE DATA FROM WORKER PROCESSES FOR CHAT PROTOCOL.
        // TODO: DATA SENT TO THE SERVER SHOULD ALREADY BE VERIFIED BY THE WORKER PROCESSES.
        // TODO: IMPLIMENT A WAY TO KNOW WHEN TO SEND REVIVING SOCKET OR CLIENT DATA, WHAT WHAT DATA.
        else if(fd == server->pipe_fd)
        {
            //TODO: IF STATEMENT FOR REVIVING GOES HERE.
            struct revive_message message; // information for socket to be revived.

            // Read revive message from the pipe and revive socket.
            revive_socket(env, err, settings, server, &message);

            // If marked for closing, close the connection.
            if(message.closed)
            {
                close_fd = message.fd;
            }

            //TODO: ELSE STATEMENT FOR CLIENT DATA TO BROADCAST GOES HERE.
            //TODO: ELSE STATEMENT FOR UPDATES FROM CLIENT FOR DATABASE GO HERES.
        }

        // If not listening socket or pipe, then it is a client socket ready to be read.
        // Read the data from the client socket and write to the domain socket to be sent to the worker processes.
        //TODO: DOMAIN SOCKET SHOULD BE ABLE TO BROADCAST, UPDATE, OR WRITE SOCKET TO DOMAIN SOCKET.
        else
        {
            poll_fd->events = 0;
            write_socket_to_domain_socket(env, err, settings, server, fd);
        }
    }

    // If the connection is to be closed, close the connection.
    if(close_fd > -1)
    {
        close_connection(env, err, settings, server, close_fd);
    }

    return close_fd != -1;
}

// Accept a connection from a client and adds to the poll file descriptor array.
static void accept_connection(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server)
{
    struct sockaddr_in client_address;
    socklen_t client_address_len;
    int client_socket;

    DC_TRACE(env);

    // Allocate memory and accept the connection.
    client_address_len = sizeof(client_address);
    client_socket = dc_accept(env, err, server->listening_socket, (struct sockaddr *)&client_address, &client_address_len);

    // Add the new connection to the poll file descriptor array.
    // Resize the memory in the array if needed.
    server->poll_fds = (struct pollfd *)dc_realloc(env, err, server->poll_fds, (server->num_fds + 2) * sizeof(struct pollfd));
    // Add the new connection to the poll file descriptor array.
    server->poll_fds[server->num_fds].fd = client_socket;
    // Poll for changes in the file descriptor, data to be read.
    server->poll_fds[server->num_fds].events = POLLIN | POLLHUP;
    // reset events to read.
    server->poll_fds[server->num_fds].revents = 0;
    // Increment the number of file descriptors.
    server->num_fds++;
    // Display the connection information.
    print_socket(env, err, "Accepted connection from", client_socket, settings->verbose_server);
}

// Writing a client socket to a worker process through domain socket,
// This code should not be changed.
static void write_socket_to_domain_socket(const struct dc_env *env, struct dc_error *err, const struct settings *settings, const struct server_info *server, int client_socket)
{
    struct msghdr msg;
    struct iovec iov;
    char control_buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;

    // Following is a metadata to send a file descriptor through a domain socket.
    // This code should NOT be changed for the chat protocol.
    DC_TRACE(env);
    dc_memset(env, &msg, 0, sizeof(msg));
    dc_memset(env, &iov, 0, sizeof(iov));
    dc_memset(env, control_buf, 0, sizeof(control_buf));
    iov.iov_base = &client_socket;
    iov.iov_len = sizeof(client_socket);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf;
    msg.msg_controllen = sizeof(control_buf);
    cmsg = CMSG_FIRSTHDR(&msg);

    if(cmsg)
    {
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *((int *) CMSG_DATA(cmsg)) = client_socket;
        print_fd(env, "Sending to client", client_socket, settings->verbose_server);

        // Send the client listening_socket descriptor to the domain listening_socket
        dc_sendmsg(env, err, server->domain_socket, &msg, 0);
    }
    else
    {
        char *error_message;

        error_message = dc_strerror(env, err, errno);
        DC_ERROR_RAISE_SYSTEM(err, error_message, errno);
    }
}

// Revive a socket that was closed by a client, this code should remain unchanged.
static void revive_socket(const struct dc_env *env, struct dc_error *err, const struct settings *settings, const struct server_info *server, struct revive_message *message)
{
    DC_TRACE(env);

    // Wait for the domain listening_socket to be available.
    dc_sem_wait(env, err, server->domain_sem);
    // Read the message from the pipe and put in the revive_message struct.
    dc_read(env, err, server->pipe_fd, message, sizeof(*message));

    // If there was no error, revive the listening_socket.
    if(dc_error_has_no_error(err))
    {
        print_fd(env, "Reviving listening_socket", message->fd, settings->verbose_server);
        dc_sem_post(env, err, server->domain_sem);

        // because the first two file descriptors are the listening_socket and pipe,
        // the index starts with the first client listening_socket.
        // Finding the correct client listening socket and revive it.
        for(int i = 2; i < server->num_fds; i++)
        {
            struct pollfd *pfd;

            pfd = &server->poll_fds[i];

            // Revive the listening_socket to read data from and listen for disconnects.
            if(pfd->fd == message->fd)
            {
                pfd->events = POLLIN | POLLHUP;
            }
        }
    }
}

// Close a connection to a client, code should not be changed.
static void close_connection(const struct dc_env *env, struct dc_error *err, const struct settings *settings, struct server_info *server, int client_socket)
{
    DC_TRACE(env);
    print_fd(env, "Closing", client_socket, settings->verbose_server);
    // Close the client listening_socket.
    dc_close(env, err, client_socket);

    // Shifting the file descriptors in the poll file descriptor array to the left.
    for(int i = 0; i < server->num_fds; i++)
    {
        if(server->poll_fds[i].fd == client_socket)
        {
            for(int j = i; j < server->num_fds - 1; j++)
            {
                server->poll_fds[j] = server->poll_fds[j + 1];
            }

            break;
        }
    }

    // Reduce the number of file descriptors.
    server->num_fds--;

    // If server and no more clients, free the poll file descriptor array.
    if(server->num_fds == 0)
    {
        free(server->poll_fds);
        server->poll_fds = NULL;
    }

    // If there are still clients, reallocate the poll file descriptor array.
    else
    {
        server->poll_fds = (struct pollfd *)realloc(server->poll_fds, server->num_fds * sizeof(struct pollfd));
    }
}

// Server process is closing and waiting for the workers to finish, code should NOT be changed.
static void wait_for_workers(const struct dc_env *env, struct dc_error *err, struct server_info *server)
{
    DC_TRACE(env);

    // since the children have the signal handler too they will also be notified, no need to kill them
    for(int i = 0; i < server->num_workers; i++)
    {
        int status;

        do
        {
            dc_waitpid(env, err, server->workers[i], &status, WUNTRACED
                                                              #ifdef WCONTINUED
                                                              | WCONTINUED
#endif
            );
        }
        while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }

    dc_close(env, err, server->listening_socket);
}

static void worker_process(struct dc_env *env, struct dc_error *err, struct worker_info *worker, const struct settings *settings)
{
    pid_t pid;

    DC_TRACE(env);

    // Set the tracer to the default tracer if debug is enabled.
    if(settings->debug_handler)
    {
        dc_env_set_tracer(env, dc_env_default_tracer);
    }

    // Otherwise set the tracer to NULL.
    else
    {
        dc_env_set_tracer(env, NULL);
    }

    // Get the pid of the worker process.
    pid = dc_getpid(env);
    printf("Started worker (%d)\n", pid);

    // Main worker loop to process messages.
    // 'done' is a necessary global variable, do NOT remove.
    while(!done)
    {
        // Process incoming messages from the client.
        process_message(env, err, worker, settings);

        if(dc_error_has_error(err))
        {
            printf("%d : %s\n", getpid(), dc_error_get_message(err));
            dc_error_reset(err);
        }
    }

    // If out of the loop, worker is done so close IPC and exit.
    dc_close(env, err, worker->domain_socket);
    dc_close(env, err, worker->pipe_fd);
}

// The worker process reading from the domain socket for the client socket.
// This code should NOT be changed.
//TODO: REPLICATE HOW WORKER READS DOMAIN SOCKET
// FOR DATA FROM MAIN PROCESS IN ANOTHER FUNCTION FOR CHAT PROTOCOL IMPLEMENTATION.
static bool extract_message_parameters(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, int *client_socket, int *value)
{
    struct msghdr msg;
    char buf[CMSG_SPACE(sizeof(int) * 2)];
    struct iovec io;
    struct cmsghdr *cmsg;
    fd_set read_fds;
    int result;
    bool got_message;

    DC_TRACE(env);

    // Metadata for receiving file descriptor from main server process.
    // the file descriptor is the client socket to communicate on.
    // this should NOT be changed when implementing the chat protocol.
    dc_memset(env, &msg, 0, sizeof(msg));
    dc_memset(env, &io, 0, sizeof(io));
    dc_memset(env, buf, '\0', sizeof(buf));
    io.iov_base = value;
    io.iov_len = sizeof(*value);

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    FD_ZERO(&read_fds);
    FD_SET(worker->domain_socket, &read_fds);

    // Waiting for domain socket to be free for reading.
    dc_sem_wait(env, err, worker->select_sem);

    // checks if the server program is done, if so got message is false.
    // 'done' is a necessary global variable, do NOT remove.
    if(done)
    {
        got_message = false;
    }

    // If not done, worker will read from the domain socket to get client socket from main server process.
    else
    {
        // Worker waits for a message from the server through the domain socket.
        result = dc_select(env, err, worker->domain_socket + 1, &read_fds, NULL, NULL, NULL);

        // Worker process received.
        if(result > 0)
        {
            // Read the message from the domain socket and sets read as true.
            dc_recvmsg(env, err, worker->domain_socket, &msg, 0);
            got_message = true;
        }

        // Worker process did not receive.
        else
        {
            got_message = false;
        }

        // Worker process is done reading from the domain socket.
        dc_sem_post(env, err, worker->select_sem);

        // Worker process sets the client socket to the received client socket from
        // the main server process.
        if(got_message)
        {
            cmsg = CMSG_FIRSTHDR(&msg);
            (*client_socket) = *((int *) CMSG_DATA(cmsg));
        }
    }

    return got_message;
}

// Used by the worker process to process messages from the client.
// TODO:BE CAUTIOUS CHANGING CODE HERE, WORKER USES PIPES TO REVIVE CLIENT SOCKETS.**********
// TODO: MODIFY READER, PROCESSOR, AND SENDER FROM ECHO.C TO IMPLEMENT CHAT PROTOCOL.
// TODO: MAY NEED TO CHANGE CODE HERE FOR CHAT PROTOCOL IMPLEMENTATION.
static void process_message(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, const struct settings *settings)
{
    int client_socket;
    int fd;
    bool got_message;

    // Extract the message parameters from the domain socket to get the client socket.
    client_socket = -1;
    got_message = extract_message_parameters(env, err, worker, &client_socket, &fd);

    // If worker process received the client socket from the main server process and
    // had no errors
    if(got_message && dc_error_has_no_error(err))
    {
        uint8_t *raw_data;
        ssize_t raw_data_length;
        bool closed;

        // Worker process reads the raw data from the client.
        print_fd(env, "Started working on", fd, settings->verbose_handler);
        raw_data = NULL;
        // use reader from the passed in library to read the data from the client socket.
        raw_data_length = worker->message_handler.reader(env, err, &raw_data, client_socket);
        closed = true; // (D'Arcy Note) set it to true so if the client forgets to set it the connection is closed which is probably bad for some things - making it noticed, also if there is an issue reading/writing probably should close.

        // If no errors when reading, process the raw data and send reply.
        if(dc_error_has_no_error(err))
        {
            // If the raw data length is 0, the client has closed the connection.
            if(raw_data_length == 0)
            {
                closed = true;
            }

            // Else there is data to process.
            else
            {
                uint8_t *processed_data;
                size_t processed_data_length;

                // Process the raw data received.
                processed_data = NULL;
                // use processor from the passed in library to process the data.
                processed_data_length = worker->message_handler.processor(env, err, raw_data, &processed_data, raw_data_length);

                // If no errors when processing, send the processed data to the client.
                if(dc_error_has_no_error(err))
                {
                    // use sender from the passed in library to send the data to the client.
                    worker->message_handler.sender(env, err, processed_data, processed_data_length, client_socket, &closed);
                }

                // Free the processed data.
                if(processed_data)
                {
                    dc_free(env, processed_data);
                }
            }
        }

        // Free the raw data.
        if(raw_data)
        {
            dc_free(env, raw_data);
        }

        // Revive the client socket.
        print_fd(env, "Done working on", fd, settings->verbose_handler);
        // Use the pipe to communicate to main process to revive client socket.
        send_revive(env, err, worker, client_socket, fd, closed);
    }
}

// Worker uses pipes to communicate with main server process to revive client sockets.
// do NOT change code here.
// TODO: NOTE HOW WORKER COMMUNICATES WITH MAIN PROCESS WITH WRITING TO PIPE, DONT CHANGE CODE.
static void send_revive(const struct dc_env *env, struct dc_error *err, struct worker_info *worker, int client_socket, int fd, bool closed)
{
    struct revive_message message;

    DC_TRACE(env);
    dc_memset(env, &message, 0, sizeof(message));
    message.fd = fd;
    message.closed = closed;
    dc_sem_wait(env, err, worker->domain_sem);
    dc_write(env, err, worker->pipe_fd, &message, sizeof(message));
    dc_sem_post(env, err, worker->domain_sem);
    dc_close(env, err, client_socket);
}

// For debugging purposes, should not be changed for chat server protocol.
static void print_fd(const struct dc_env *env, const char *message, int fd, bool display)
{
    DC_TRACE(env);

    if(display)
    {
        printf("(pid=%d) %s with FD %d\n", getpid(), message, fd);
    }
}

// for differentiating between connected clients.
static void print_socket(const struct dc_env *env, struct dc_error *err, const char *message, int socket, bool display)
{
    DC_TRACE(env);

    if(display)
    {
        struct sockaddr_in peer_address;
        socklen_t peer_address_len;
        uint16_t port;
        char *printable_address;

        peer_address_len = sizeof(peer_address);
        dc_getpeername(env, err, socket, (struct sockaddr *)&peer_address, &peer_address_len);

        printable_address = dc_inet_ntoa(env, peer_address.sin_addr);
        port = dc_ntohs(env, peer_address.sin_port);
        printf("(pid=%d) %s: %s:%d - %d\n", getpid(), message, printable_address, port, socket);
    }
}
