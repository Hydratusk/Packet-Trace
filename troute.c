/*
 * Publisher is the server that works on top of CCNx
 * and notifies other nodes of it's existance. Basically,
 * it's role is to notify other nodes about how they can
 * access it.
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <errno.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/schedule.h>
#include <ccn/hashtb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/fcntl.h>

#include <glib.h>
/*
 * Structure holding info about our server
 *
 * @param prefix  Path that the server is installed at
 * @param expire  Sets the freshenss on the information of this 
 *                server, before it expires
 * @param iface   The interface which this server is running at
 * @param socket  Our socket server listening to ports and saving stuff
 */
struct ccn_info_server {
    struct ccn         *ccn;
    struct ccn_charbuf *prefix_server;
    struct ccn_closure  closure_server;

    int                 expire;
    int                 count;

    char                server[NI_MAXHOST];
    int                 port;

    /* tcp client stuff */
    int                 socket;

    bool                init;
    struct sockaddr_in  serv;

};

#define SERVER_SUFFIX "where"
#define BUF_SIZE      64*1024

/*
 * Blurts out usage information
 *
 * @param progname Name of the program, argv[0].
 */
static void usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s ccnx:/name/prefix\n"
            "Starts an info server that responds to request for Interest name ccnx:/name/prefix/server \n"
            " -h - print this message and exit\n",
            progname);
    exit(1);
}

/*
 * Create the TCP and CCN servers and loop till someone kills you
 *
 * @param server The mastermind the almighty one.
 */
void loop( struct ccn_info_server *server ){

    while(true){
      ccn_run(server->ccn, 10);
    }

    close(server->socket);

    ccn_destroy(&(server->ccn));
    ccn_charbuf_destroy(&server->prefix_server);
}

/*
 * Creates the prefixes that we are gonna listen on
 *
 * @param server    our server holding information about everything and beyond
 * @param argv      command line parameters passed to us
 * @param progname  name of the program
 */
void create_ccn_prefixes( struct ccn_info_server *server, char **argv, const char *progname ){
    int res;

    server->prefix_server = ccn_charbuf_create();

    res = ccn_name_from_uri(server->prefix_server, argv[0]);

    if (res < 0) {
        fprintf(stderr, "%s: bad ccn URI: %s\n", progname, argv[0]);
        exit(1);
    }
    if (argv[1] != NULL){
        fprintf(stderr, "%s warning: extra arguments ignored\n", progname);
        fprintf(stderr, "%s \n", (char*)argv[1]);
        fprintf(stderr, "%s \n", (char*)argv[0]);
    }

    //append "/server" to the given name prefix
    res = ccn_name_append_str(server->prefix_server, SERVER_SUFFIX);
    if (res < 0) {
        fprintf(stderr, "%s: error constructing ccn URI: %s/%s\n", progname, argv[0], SERVER_SUFFIX);
        exit(1);
    }
}


static enum ccn_upcall_res server_interest(struct ccn_closure* selfp,
        enum ccn_upcall_kind kind, struct ccn_upcall_info* info)
{
  const unsigned char *buf;
  char *ip_port = NULL;
  size_t length;
  struct ccn_info_server *server = (struct ccn_info_server*)selfp->data;

  switch(kind) {
    case CCN_UPCALL_FINAL:
      break;
    case CCN_UPCALL_CONTENT:
      ccn_content_get_value( info->content_ccnb, info->pco->offset[CCN_PCO_E], info->pco, &buf, length );
      ip_port = strdup( buf );

      fprintf(stderr, "Content  : %s\n", ip_port);
      // Extract IP address
      char *tok = strtok( ip_port, ":" );
      
      strncpy( server->server, tok, NI_MAXHOST );
      inet_aton( server->server, &server->serv.sin_addr );
      // Extract Port address
      tok = strtok( NULL, ":" );
      server->port = atoi( tok );

      fprintf(stderr, "Server: %s\nPort: %d\n", server->server, server->port );
      free( ip_port );

      server->init = true;
      break;
    default:
      break;
  }

  return CCN_UPCALL_RESULT_OK;
}

void create_ccn_daemon( struct ccn_info_server *server ){
    int res;
    server->closure_server.p  = &server_interest;
    server->closure_server.data = (void*)server;

    /* Connect to ccnd */
    server->ccn = ccn_create();
    if (ccn_connect(server->ccn, NULL) == -1) {
        perror("Could not connect to ccnd");
        exit(1);
    }
}

void setup_server( struct ccn_info_server *server ){
  char buffer[64*1024+1];
  server->serv.sin_family = AF_INET;
  server->serv.sin_port   = htons( server->port );
  server->socket = socket(AF_INET,SOCK_STREAM,0);

  if ( connect( server->socket, (struct sockaddr*)&server->serv, sizeof(server->serv ) ) >= 0 ){
    FILE *fp = popen( "ccnnamelist $HOME/repoFile1", "r" );

    while( fgets( buffer, sizeof(buffer)-1, fp ) != NULL ) {
      send( server->socket, buffer, strlen( buffer ), 0 );
    }

    pclose( fp );
    close( server->socket );
  }
}
/*
 * Main method, Ruling the world since 1972
 */
int main(int argc, char **argv)
{
    const char *progname = argv[0];
    struct ccn_info_server server = {.count = 0, .expire = 1, .ccn = NULL, .init = false};

    // read the options and set the parameters
    int res;
    while ((res = getopt(argc, argv, "hx:")) != -1) {
        switch (res) {
            case 'x':
                server.expire = atol(optarg);
                if (server.expire <= 0)
                    usage(progname);
                break;
            case 'h':
            default:
                usage(progname);
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argv[0] == NULL)
        usage(progname);

    // Create the CCN prefixes and get ready to startup the server
    create_ccn_prefixes( &server, argv, progname );
    create_ccn_daemon( &server );

    // Fetch the ip/port of the server
    ccn_express_interest( 
        server.ccn, 
        server.prefix_server, 
        &server.closure_server, 
        NULL );

    while( true ){
      ccn_run( server.ccn, 500 );

      if ( server.init ) {
        server.init = false;
        setup_server( &server );
      }
    }

    // Do the generic loop for the server

    ccn_destroy(&(server.ccn));
    exit(0);
}
