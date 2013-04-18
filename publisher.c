/*
 * Publisher is the server that works on top of CCNx
 * and notifies other nodes of it's existance. Basically,
 * it's role is to notify other nodes about how they can
 * access it.
 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

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

struct _GRelation
{
  gint fields;
  gint current_field;
  
  GHashTable   *all_tuples;
  GHashTable  **hashed_tuple_tables;
  
  gint count;
};
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

    /* Interests residing on /server path */
    struct ccn_closure  closure_server;
    struct ccn_charbuf *prefix_server;

    /* Interests residing on /where path */
    struct ccn_closure  closure_where;
    struct ccn_charbuf *prefix_where;

    /* Table of relations */
    GRelation   *relations;

    int                 expire;
    char                host[NI_MAXHOST];
    int                 port;
    int                 count;

    /* tcp server stuff */
    int                 socket;
    struct sockaddr_in  serv;
};

#define SERVER_SUFFIX "server"
#define WHERE_SUFFIX  "where"
#define BUF_SIZE      64*1024

/*
 * Blurts out usage information
 *
 * @param progname Name of the program, argv[0].
 */
static void usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s ccnx:/name/prefix -i interface -p port\n"
            "Starts an info server that responds to request for Interest name ccnx:/name/prefix/server \n"
            " -h - print this message and exit\n"
            " -i - the interface we will be listening on\n"
            " -p - the port that our server would be listening on for incoming connections\n"
            " -x - set FreshnessSeconds\n",
            progname);
    exit(1);
}


/*
 * extracts the ip address of the specific interface so others can connect to it
 *
 * @param iface   the interface to save the ip address from
 * @param server  our server instance that is going to keep the server address
 */
void extract_ip(  const char *iface, struct ccn_info_server *server ){
  struct ifaddrs *ifaddr, *ifa;
  int family, s;

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    exit(EXIT_FAILURE);
  }

  /* Walk through linked list, maintaining head pointer so we
     can free list later */

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;

    family = ifa->ifa_addr->sa_family;

    /* Display interface name and family (including symbolic
       form of the latter for the common families) */

    if (strcmp( iface, ifa->ifa_name ) != 0 || family != 2){
      continue;
    }

    /* For an AF_INET* interface address, display the address */
    if (family == AF_INET || family == AF_INET6) {
      s = getnameinfo(ifa->ifa_addr,
          (family == AF_INET) ? sizeof(struct sockaddr_in) :
          sizeof(struct sockaddr_in6),
          server->host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
      if (s != 0) {
        printf("getnameinfo() failed: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
      }

      fprintf( stderr, "Host : %s\n", server->host );
    }
  }

  freeifaddrs(ifaddr);
}

/*
 * Checks whether the interest name is valid
 * We are expecting ccnx:/name/prefix/server format
 * @return 1 if interest name is valid, 0 otherwise
 *
 * @param prefix        The prefix that the interest should be matched against
 * @param interest_msg  RAW Interest message
 * @param pi            Prased Interest message
 *
 * @return 1 if the interest is valid, otherwise 0.
 */
int info_interest_valid(struct ccn_charbuf *prefix,
        const unsigned char *interest_msg, const struct ccn_parsed_interest *pi)
{
    struct ccn_indexbuf *prefix_components;
    int prefix_ncomps;

    prefix_components = ccn_indexbuf_create();
    prefix_ncomps = ccn_name_split(prefix, prefix_components);
    ccn_indexbuf_destroy(&prefix_components);

    /* We don't care about the rest
    if (pi->prefix_comps == prefix_ncomps) {
      return 1;
    }
    */

    return 1;
}

/*
 * Build an info response, returning the IP address of the chosen interface
 *
 * @param h     ccn handler object, required by everything related to ccn
 * @param data  same thing as handler, required by everything related to ccn
 *
 * @return 0 if we are successful for signing the content, else -1.
 */
int construct_info_response(struct ccn *h, struct ccn_charbuf *data, 
        const unsigned char *interest_msg, const struct ccn_parsed_interest *pi, struct ccn_info_server *server)
{
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    int res;
    char buffer[NI_MAXHOST+6];

    ccn_charbuf_append(name, interest_msg + pi->offset[CCN_PI_B_Name],
            pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);

    //set freshness seconds
    if (server->expire >= 0) {
        sp.template_ccnb = ccn_charbuf_create();
        ccn_charbuf_append_tt(sp.template_ccnb, CCN_DTAG_SignedInfo, CCN_DTAG);
        ccnb_tagged_putf(sp.template_ccnb, CCN_DTAG_FreshnessSeconds, "%ld", server->expire);
        sp.sp_flags |= CCN_SP_TEMPL_FRESHNESS;
        ccn_charbuf_append_closer(sp.template_ccnb);
    }

    /*
     * TODO: Make sure we are adding our IP and Port of the server here
     */
    sprintf( buffer, "%s:%d", server->host, server->port );
    res = ccn_sign_content(h, data, name, &sp, buffer, strlen(buffer));

    ccn_charbuf_destroy(&sp.template_ccnb);
    ccn_charbuf_destroy(&name);
    return res;
}


/*
 * Build a where response, returning the location of a resource on the
 * network based on the information that clients passed to us
 *
 * @param h     ccn handler object, required by everything related to ccn
 * @param data  same thing as handler, required by everything related to ccn
 *
 * @return 0 if we are successful for signing the content, else -1.
 */
int construct_where_response(struct ccn *h, struct ccn_charbuf *data, 
        const unsigned char *interest_msg, const struct ccn_parsed_interest *pi, struct ccn_info_server *server, const char *buffer)
{
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    int res;
    char output[BUF_SIZE+1];
    int pointer = 0;

    memset( output, '\0', sizeof(output) );

    ccn_charbuf_append(name, interest_msg + pi->offset[CCN_PI_B_Name],
            pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);

    //set freshness seconds
    if (server->expire >= 0) {
        sp.template_ccnb = ccn_charbuf_create();
        ccn_charbuf_append_tt(sp.template_ccnb, CCN_DTAG_SignedInfo, CCN_DTAG);
        ccnb_tagged_putf(sp.template_ccnb, CCN_DTAG_FreshnessSeconds, "%ld", server->expire);
        sp.sp_flags |= CCN_SP_TEMPL_FRESHNESS;
        ccn_charbuf_append_closer(sp.template_ccnb);
    }

    printf("Building out message: %s\n %s\n", buffer, output);

    GTuples *t = g_relation_select( server->relations, buffer, 0 );
    int i;
    for ( i = 0; i < t->len; ++i ){
      const char *ip = g_tuples_index( t, i, 1 );
      strncpy( output + pointer, ip, strlen( ip ) );
      pointer += (strlen(ip)+1);
      output[pointer+1]='\n';
    }

    printf("Building out message: %s\n %s\n", buffer, output);

    // Now we need to extract the data from our relation database
    res = ccn_sign_content(h, data, name, &sp, output, strlen(output));

    ccn_charbuf_destroy(&sp.template_ccnb);
    ccn_charbuf_destroy(&name);
    return res;
}

/*
 * Called when we we have an incoming request
 *
 * @param selfp A pointer to the closure that has this function as it's handler
 * @param kind  Kind of Upcall even that we got
 * @param info  Information about the upcall interest packet
 *
 * @return Upcall response status
 */
enum ccn_upcall_res server_interest(struct ccn_closure *selfp,
    enum ccn_upcall_kind kind, struct ccn_upcall_info *info)
{
  struct ccn_info_server *server = selfp->data;
  int res;

  switch (kind) {
    case CCN_UPCALL_FINAL:
      break;
    case CCN_UPCALL_INTEREST:
      /*
       * TODO: Tweak here to check whether the 
       * call is for where a specific packet 
       * is or where the server is at.
       */
      if (info_interest_valid(server->prefix_server, info->interest_ccnb, info->pi)) {
        //construct Data content with given Interest name
        struct ccn_charbuf *data = ccn_charbuf_create();
        construct_info_response(info->h, data, info->interest_ccnb, info->pi, server);

        //send response back
        res = ccn_put(info->h, data->buf, data->length);
        ccn_charbuf_destroy(&data);

        // TODO: Do I need this?
        server->count ++;

        if (res >= 0)
          return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
      }
      break;
    default:
      break;
  }

  return CCN_UPCALL_RESULT_OK;
}

/*
 * Called when we we have an incoming request
 *
 * @param selfp A pointer to the closure that has this function as it's handler
 * @param kind  Kind of Upcall even that we got
 * @param info  Information about the upcall interest packet
 *
 * @return Upcall response status
 */
enum ccn_upcall_res where_interest(struct ccn_closure *selfp,
        enum ccn_upcall_kind kind, struct ccn_upcall_info *info)
{
  struct ccn_info_server *server = selfp->data;

  int res;

  switch (kind) {
    case CCN_UPCALL_FINAL:
      break;
    case CCN_UPCALL_INTEREST:
      /*
       * TODO: Tweak here to check whether the 
       * call is for where a specific packet 
       * is or where the server is at.
       */
      if (info_interest_valid(server->prefix_server, info->interest_ccnb, info->pi)) {
        const unsigned char *buf;
        char *what = NULL;
        size_t length;

        //construct Data content with given Interest name
        struct ccn_charbuf *data = ccn_charbuf_create();
        ccn_name_comp_get( info->interest_ccnb, info->interest_comps, info->interest_comps->n-2, &buf, &length);

        what = strdup( (const char*)buf );

        construct_where_response(info->h, data, info->interest_ccnb, info->pi, server, what);

        //send response back
        res = ccn_put(info->h, data->buf, data->length);
        ccn_charbuf_destroy(&data);
        free( what );

        // TODO: Do I need this?
        server->count ++;

        if (res >= 0)
          return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
      }
      break;
    default:
      break;
  }

  return CCN_UPCALL_RESULT_OK;
}


/*
 * Create the CCN server and create 2 interest filters
 * on both data types.
 *
 * @param server the server containing the CCN structure
 *               and prefixes with corresponding closures
 */
void create_ccn_server( struct ccn_info_server *server ){
    int res;
    server->closure_server.p  = &server_interest;
    server->closure_where.p   = &where_interest;

    /* Connect to ccnd */
    server->ccn = ccn_create();
    if (ccn_connect(server->ccn, NULL) == -1) {
        perror("Could not connect to ccnd");
        exit(1);
    }

    server->closure_server.data = server;
    res = ccn_set_interest_filter(server->ccn, server->prefix_server, &server->closure_server);
    if (res < 0) {
        fprintf(stderr, "Failed to register interest (res == %d)\n", res);
        exit(1);
    }

    server->closure_where.data = server;
    res = ccn_set_interest_filter(server->ccn, server->prefix_where, &server->closure_where);
    if (res < 0) {
        fprintf(stderr, "Failed to register interest (res == %d)\n", res);
        exit(1);
    }
}

/*
 * Create a socket and listen on a certain port, the port is given by the server
 *
 * @param server The server that has the port and the socket structure
 *
 */
void create_tcp_server( struct ccn_info_server *server ){

  memset(&server->serv, 0, sizeof(server->serv));           /* zero the struct before filling the fields */
  server->serv.sin_family       = AF_INET;                  /* set the type of connection to TCP/IP */
  server->serv.sin_addr.s_addr  = htonl(INADDR_ANY);        /* set our address to any interface */
  server->serv.sin_port         = htons(server->port);           /* set the server port number */    

  server->socket = socket(AF_INET, SOCK_STREAM, 0);
  fcntl(server->socket, F_SETFL, O_NONBLOCK);

  /* bind serv information to mysocket */
  bind(server->socket, (struct sockaddr *)&(server->serv), sizeof(struct sockaddr));

}

/*
 * Parses a tcp packet received from one of the clients, the procedure involves
 * extracting the meta data about the remove repository 
 *
 * @param server The server that has the port and the socket structure
 *
 */
void parse_tcp_packet( struct ccn_info_server *server, char *buffer, struct sockaddr_in *dest ){

  char addr[NI_MAXHOST];

  getnameinfo((const struct sockaddr*)dest,
      sizeof(struct sockaddr_in),
      addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

  char *buf = strdup( buffer );
  char *pch = strtok( buf, "\n" );

  // Remove all the ip instances in our mini database
  g_relation_delete( server->relations, addr, 1 );

  while ( pch != NULL ){
    // Add the Data->Ip relationship
    g_relation_insert( server->relations, strdup(pch), strdup(addr) );

    fprintf( stderr, "Got : %s\n", pch );
    pch = strtok( NULL, "\n" );
  }



  free(buf);
}

/*
 * Check for any pending connections, open them up, recv stuff
 * parse those stuff and be DONE.
 * 
 * @param server contains our server socket instance
 */
void tcp_run( struct ccn_info_server *server ){
  socklen_t socksize = sizeof(struct sockaddr_in);
  struct sockaddr_in dest; /* socket info about the machine connecting to us */

  /* start listening, allowing a queue of up to 1 pending connection */
  listen(server->socket, 1);
  int consocket = accept(server->socket, (struct sockaddr *)&dest, &socksize);

  if ( consocket != -1 ) {
    char buffer[64*1024+1];
    char *ptr = buffer;

    // Make sure we are listening doing a 
    fcntl(consocket, F_SETFL, !O_NONBLOCK);

    // Read the sent message, and parse it
    int size = 0;
    
    while( (size = recv( consocket, (void*)ptr, 64*1024, 0 ) ) != 0 ) {
      ptr += size;
    }

    // Parse
    parse_tcp_packet( server, buffer, &dest );

    send(consocket, "OK", 3, 0); 
    close(consocket);
  }
}

/*
 * Create the TCP and CCN servers and loop till someone kills you
 *
 * @param server The mastermind the almighty one.
 */
void loop( struct ccn_info_server *server ){
    create_ccn_server( server );
    create_tcp_server( server );

    while(true){
      ccn_run(server->ccn, 500);
      tcp_run(server);
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
    server->prefix_where  = ccn_charbuf_create();

    res = ccn_name_from_uri(server->prefix_server, argv[0]);
    res = ccn_name_from_uri(server->prefix_where , argv[0]);

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

    res = ccn_name_append_str(server->prefix_where, WHERE_SUFFIX);
    if (res < 0) {
        fprintf(stderr, "%s: error constructing ccn URI: %s/%s\n", progname, argv[0], WHERE_SUFFIX);
        exit(1);
    }
}

/*
 * Creates the hash tables that we use to save information on
 *
 * @param server    our server holding information about everything and beyond
 */
void create_hash_tables( struct ccn_info_server *server ){
  server->relations = g_relation_new(2);
  g_relation_index( server->relations, 0, g_str_hash, g_str_equal );
  g_relation_index( server->relations, 1, g_str_hash, g_str_equal );
}


/*
 * Main method, Ruling the world since 1972
 */
int main(int argc, char **argv)
{
    const char *progname = argv[0];
    struct ccn_info_server server = {.count = 0, .expire = 1, .ccn = NULL};

    // read the options and set the parameters
    int res;
    while ((res = getopt(argc, argv, "hx:i:p:")) != -1) {
        switch (res) {
            case 'x':
                server.expire = atol(optarg);
                if (server.expire <= 0)
                    usage(progname);
                break;
            case 'i':
                extract_ip( optarg, &server );
                break;
            case 'p':
                server.port = atol(optarg);
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
    create_hash_tables( &server );

    // Do the generic loop for the server
    loop( &server );

    g_relation_destroy( server.relations );
    exit(0);
}
