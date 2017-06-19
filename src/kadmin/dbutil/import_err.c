/*
 * et-c-import_err.c:
 * This file is automatically generated; please do not edit it.
 */
#if defined(_WIN32)
# include "win-mac.h"
#endif

#if !defined(_WIN32)
extern void initialize_imp_error_table (void);
#endif

#define N_(x) (x)

/* Lclint doesn't handle null annotations on arrays
   properly, so we need this typedef in each
   generated .c file.  */
/*@-redef@*/
typedef /*@null@*/ const char *ncptr;
/*@=redef@*/

static ncptr const text[] = {
	N_("Input not recognized as database dump"),
	N_("Bad token in dump file."),
	N_("Bad version in dump file"),
	N_("Defective record encountered: "),
	N_("Truncated input file detected."),
	N_("Import of dump failed"),
	N_("Number of records imported does not match count"),
	N_("Unknown command line option.\nUsage: ovsec_adm_import [filename]"),
	N_("Warning -- continuing to import will overwrite existing databases!"),
	N_("Database rename Failed!!"),
	N_("Extra data after footer is ignored."),
	N_("Proceed <y|n>?"),
	N_("while opening input file"),
	N_("while importing databases"),
	N_("cannot open /dev/tty!!"),
	N_("while opening databases"),
	N_("while acquiring permanent lock"),
	N_("while releasing permanent lock"),
	N_("while closing databases"),
	N_("while retrieving configuration parameters"),
    "mit-krb5", /* Text domain */
    0
};

#include <com_err.h>

const struct error_table et_imp_error_table = { text, 37349888L, 20 };

#if !defined(_WIN32)
void initialize_imp_error_table (void)
    /*@modifies internalState@*/
{
    (void) add_error_table (&et_imp_error_table);
}
#endif