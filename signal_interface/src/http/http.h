#include <stdlib.h>
#include <string>
#include <civetweb.h>
#include "../../../db_interface/src/axolotl/Account.h"
#include "./handlers/decrypt.h"
#include "./handlers/encrypt.h"
#include "./handlers/keyBundle.h"

void http_init(char *dbPath, char *port, char *pass);
void http_shutdown();