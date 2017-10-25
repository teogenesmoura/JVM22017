#ifndef DECODE
	#define DECODE

	#ifdef LEITOR_SERVER
		#define EXT_LEITOR
	#else
		#define EXT_LEITOR extern
	#endir

	#define	INSTRUC_NAME	35

	typedef struct {
		char instruc[INSTRUC_NAME];
		int byte;
	}decode;

	EXT_LEITOR int init_decoder(decoder *decode);

#endif