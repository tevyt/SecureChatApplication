#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"

#include "aes.h"
#include "aes.c"

#include <openssl/rsa.h>
#include "rsa.c"
#include "sha.c"

#ifndef PATH_MAX
#define PATH_MAX 1024

#endif

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;
static int authenticated = 0;

static unsigned char* clientAESKey;
static unsigned char* serverAESKey;


static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, awaiting authentication from client...\n");
	if(authenticateServer() != 0){
		error("Failure authenticating server");
	}
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

int authenticateServer(){
	unsigned char* proposed_session_key_ciphertext = malloc(RSA_KEY_LENGTH);

	size_t r = recv(sockfd,proposed_session_key_ciphertext, RSA_KEY_LENGTH, 0);

	if(r == 0 || r == -1){
		fprintf(stderr, "Error authenticating server\n");
		free(proposed_session_key_ciphertext);
		return 1;
	}

	fprintf(stderr, "Received encrypted session key.\n");

	clientAESKey = RSAdecrypt(proposed_session_key_ciphertext, "./keys/server/private.pem", AES_KEY_LENGTH);

	if(clientAESKey == NULL){
		fprintf(stderr, "Error decrypting session key.\n");
		free(proposed_session_key_ciphertext);
		return 1;
	}

	fprintf(stderr, "Decrypted session key.\n");

	serverAESKey = generateAESKey();
	fprintf(stderr, "Generated session key.\n");

	if(serverAESKey == NULL){
		fprintf(stderr, "Error generating session key.\n");
		free(proposed_session_key_ciphertext);
		free(clientAESKey);
		return 1;
	}

	unsigned char* authMessageForClient = malloc(AES_KEY_LENGTH * 2);

	memcpy(authMessageForClient, clientAESKey, AES_KEY_LENGTH);
	memcpy(authMessageForClient + AES_KEY_LENGTH, serverAESKey, AES_KEY_LENGTH);


	unsigned char* authMessageForClientCiphertext = RSAencrypt(authMessageForClient, "./keys/server/approved-clients/public.pem");

	if(authMessageForClientCiphertext == NULL){
		fprintf(stderr, "Error encrypting auth message for client.\n");
		free(proposed_session_key_ciphertext);
		free(clientAESKey);
		free(serverAESKey);
		free(authMessageForClient);
		return 1;
	}

	send(sockfd, authMessageForClientCiphertext, RSA_KEY_LENGTH, 0);

	unsigned char* clientConfirmationCipherText = malloc(RSA_KEY_LENGTH);
	recv(sockfd, clientConfirmationCipherText, RSA_KEY_LENGTH, 0);


	unsigned char* clientConfirmation = RSAdecrypt(clientConfirmationCipherText, "./keys/server/private.pem", AES_KEY_LENGTH);


	if(memcmp(clientConfirmation, serverAESKey, AES_KEY_LENGTH) != 0){
		fprintf(stderr, "Error authenticating server. Client did not provide the correct key.\n");
		free(proposed_session_key_ciphertext);
		free(clientAESKey);
		free(serverAESKey);
		free(authMessageForClient);
		free(authMessageForClientCiphertext);
		free(clientConfirmation);
		return 1;
	}else{
		fprintf(stderr, "Server authenticated.\n");
		authenticated = 1;
	}


	free(clientConfirmation);
	free(proposed_session_key_ciphertext);
	return 0;
}


static int authenticateClient(){
	const char* serverPublicKeyPath = "./keys/server/public.pem";

	clientAESKey = generateAESKey();

	if(clientAESKey == NULL){
		fprintf(stderr, "Error generating AES key.\n");
		free(serverPublicKeyPath);
		return 1;
	}

	unsigned char* encryptedClientKey = RSAencrypt(clientAESKey, serverPublicKeyPath);

	if(encryptedClientKey == NULL){
		fprintf(stderr, "Error encrypting session key.\n");
		free(serverPublicKeyPath);
		return 1;
	}

	fprintf(stderr, "Sending encrypted client key.\n");


    send(sockfd,encryptedClientKey,RSA_KEY_LENGTH,0);


	unsigned char* authMessageCipherText = malloc(RSA_KEY_LENGTH);

	size_t r = recv(sockfd,authMessageCipherText, RSA_KEY_LENGTH, 0);

	if(r == 0 || r == -1){
		fprintf(stderr, "Error authenticating client\n");
		free(authMessageCipherText);
		free(encryptedClientKey);
		return 1;
	}

	unsigned char* authMessage = RSAdecrypt(authMessageCipherText, "./keys/client/private.pem", AES_KEY_LENGTH * 2);

	if(authMessage == NULL){
		fprintf(stderr, "Error decrypting auth message.\n");
		free(authMessageCipherText);
		free(encryptedClientKey);
		return 1;
	}

	int keyMatches = memcmp(clientAESKey, authMessage, AES_KEY_LENGTH);

	if(keyMatches == 0){
		authenticated = 1;
		serverAESKey = authMessage + AES_KEY_LENGTH;
		fprintf(stderr, "Client authenticated.\n");
		unsigned char* serverKey = authMessage + AES_KEY_LENGTH;

		unsigned char* confirmationMessage = malloc(AES_KEY_LENGTH + AES_BLOCK_SIZE);

		unsigned char* serverCipher = RSAencrypt(serverAESKey, "./keys/server/public.pem");

		send(sockfd,serverCipher,RSA_KEY_LENGTH,0);
	}else{
		fprintf(stderr, "Error authenticating client. Server did not provide the correct key.\n");
		free(authMessageCipherText);
		free(encryptedClientKey);
		free(authMessage);
		return 1;
	}

	return 0;
}

static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
		error("ERROR connecting");
	}else if(authenticateClient() != 0){
		error("Failure authenticating client");
	}
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}



static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{
	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;   /* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
	size_t len = g_utf8_strlen(message,-1);
	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */
	ssize_t nbytes;

	int messageMaximumExceeded = len >= AES_CIPHERTEXT_BUFFER_SIZE;

	char* tags[2] = {messageMaximumExceeded ? "error" : "self", NULL};

	if(messageMaximumExceeded){
		tsappend("Your message is too long.\n",tags,0);
		return;
	}

	tsappend("me: ",tags,0);

	unsigned char* key = isclient ? clientAESKey : serverAESKey;
	

	struct AESCipher encryptedMessage = AESencrypt(message, key);
	const unsigned char* signature = signMessage(message, encryptedMessage.plaintextLength, encryptedMessage.ciphertextLength, encryptedMessage.initializationVector);
	encryptedMessage.signature = signature;

	printHex(signature, SHA256_DIGEST_LENGTH);


	unsigned char* buffer = convertStructToBuffer(&encryptedMessage);
	size_t totalSize = getAESCipherBufferSize();

	if ((nbytes = send(sockfd,buffer,totalSize,0)) == -1)
		error("send failed");

	tsappend(message,NULL,2);
	free(message);
	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);
}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf, "error", "foreground", "#dc322f", "font", "bold", NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void*)
{
	size_t maxlen = getAESCipherBufferSize();
	unsigned char input[maxlen]; /* might add \n and \0 */
	ssize_t nbytes;
	while (1) {
		if ((nbytes = recv(sockfd,input,maxlen,0)) == -1)
			error("recv failed");
		if (nbytes == 0) {
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}

		struct AESCipher aesCipher = convertBufferToStruct(input);
		fprintf(stderr, "Encrypted message: %02x\n", aesCipher.ciphertext[0]);
		fprintf(stderr, "Encrypted message length: %d\n", aesCipher.ciphertextLength);
		int plainTextLength = aesCipher.plaintextLength;

		unsigned char* key = isclient ? serverAESKey : clientAESKey;

		fprintf(stderr,"About to decrypt message: %d\n", plainTextLength);
		unsigned char* m = malloc(plainTextLength + 2);

		memcpy(m, AESdecrypt(aesCipher, key), plainTextLength);
		fprintf(stderr, "Decrypted message\n");

		

		fprintf(stderr, "About to make readable");
		if (m[plainTextLength - 1] != '\n')
			m[plainTextLength] = '\n';
		m[plainTextLength + 1] = 0;
		fprintf(stderr, "Made readable");

		//If authentication is complete write the message, otherwise wait for authentication to complete
		g_main_context_invoke(NULL,shownewmessage,(gpointer)m);
	}
	return 0;
}
