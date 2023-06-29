/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022-2023 IBM Corp.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <argp.h>
#include "err.h"
#include "prlog.h"
#include "generic.h"
#include "libstb-secvar.h"
#include "common/validate.h"
#include "common/util.h"
#include "common/write.h"
#include "common/verify.h"

/*
 * verify the timestamp, auth data using PK or KEK keys and
 * extract the esl data from auth data
 */
static int
update_variable (const uint8_t *variable_name, const uint8_t *auth_data,
                 const size_t auth_data_size, const uint8_t *current_esl_data,
                 const size_t current_esl_data_size, const uint8_t *pk_esl_data,
                 const size_t pk_esl_data_size, const uint8_t *kek_esl_data,
                 const size_t kek_esl_data_size, const bool append_update,
                 uint8_t **new_esl_data, size_t *new_esl_data_size)
{
  int rc = SUCCESS;
  uint8_t *label = NULL;
  uint64_t log_data;
  size_t label_size = 0;
  bool allow_unauthenticated_pk_update = false;

  if (memcmp (variable_name, PK_VARIABLE, PK_LEN) == 0)
    allow_unauthenticated_pk_update = true;

  label = get_wide_character (variable_name, strlen ((char *) variable_name));
  label_size = strlen ((char *) variable_name) * 2;

  rc = update_var_from_auth (label, label_size, auth_data, auth_data_size,
                             current_esl_data, current_esl_data_size,
                             allow_unauthenticated_pk_update, append_update, pk_esl_data,
                             pk_esl_data_size, kek_esl_data, kek_esl_data_size,
                             new_esl_data, new_esl_data_size, &log_data);
  if (label != NULL)
    free (label);

  if (verbose >= PR_INFO)
    {
      if (rc != SUCCESS && rc != DELETE_EVERYTHING)
        prlog (PR_INFO, "VERIFYING AUTH FILE: %s is FAILED (%d)\n", variable_name, rc);
      else
        prlog (PR_INFO, "VERIFYING AUTH FILE: %s is VERIFIED SUCCESSFULLY\n", variable_name);

      if (pk_esl_data == NULL)
        prlog (PR_INFO, "\tPK: not avilable\n");
      else
        prlog (PR_INFO, "\tPK: avilable\n");

      if (kek_esl_data == NULL)
        prlog (PR_INFO, "\tKEK: not avilable\n");
      else
        prlog (PR_INFO, "\tKEK: avilable\n");

      prlog (PR_INFO, "\tunauthenticated PK update: %s\n",
             (allow_unauthenticated_pk_update ? "True" : "False"));
      prlog (PR_INFO, "\tappend update: %s\n\n", (append_update ? "True" : "False"));

      if (*new_esl_data != NULL)
        {
          rc = print_variables ((*new_esl_data + TIMESTAMP_LEN),
                                (*new_esl_data_size - TIMESTAMP_LEN), variable_name);
          if (rc != SUCCESS)
            return rc;
        }
    }

  return rc;
}

/*
 * extract the ESL data and its size from ESL file
 */
static int
get_current_esl_data (const uint8_t *esl_file, uint8_t **current_esl_data,
                      size_t *current_esl_data_size)
{
  int rc = SUCCESS;
  size_t buffer_size = 0;
  uint8_t *buffer = NULL;

  if (is_file ((char *) esl_file) != SUCCESS)
    return INVALID_FILE;

  buffer = (uint8_t *) get_data_from_file ((char *) esl_file, SIZE_MAX, &buffer_size);
  if (buffer != NULL)
    {
      if (buffer_size == DEFAULT_PK_LEN)
        {
          print_raw ((char *) buffer, buffer_size);
          free (buffer);
          buffer = NULL;
          buffer_size = 0;
        }
      else if (buffer_size != TIMESTAMP_LEN)
        {
          rc = validate_esl (buffer + TIMESTAMP_LEN, buffer_size - TIMESTAMP_LEN);
          if (rc != SUCCESS)
            {
              free (buffer);
              return rc;
            }
        }
    }
  else
    return INVALID_FILE;

  *current_esl_data = buffer;
  *current_esl_data_size = buffer_size;

  return rc;
}

/*
 * extract the append header, auth data and its size from auth file
 */
static int
get_auth_data (const uint8_t *auth_file, uint8_t **auth_data, size_t *auth_data_size,
               bool *append_update)
{
  int rc = SUCCESS;
  size_t buffer_size = 0;
  uint8_t *buffer = NULL;

  if (is_file ((char *) auth_file) != SUCCESS)
    return INVALID_FILE;

  buffer = (uint8_t *) get_data_from_file ((char *) auth_file, SIZE_MAX, &buffer_size);
  if (buffer != NULL)
    {
      rc = validate_auth (buffer, buffer_size);
      if (rc != SUCCESS)
        {
          free (buffer);
          return rc;
        }
    }
  else
    return INVALID_FILE;

  *append_update = extract_append_header (buffer, buffer_size);
  *auth_data = buffer;
  *auth_data_size = buffer_size;

  return rc;
}

/*
 * extract the ESL data and its size from ESL file on given secvar path or
 * current variables
 */
static int
get_current_esl (const struct verify_args *args, const uint8_t *update_variable,
                 uint8_t **current_esl_data, size_t *current_esl_data_size)
{
  int i = 0, rc = SUCCESS;
  size_t len = 0;
  char *esl_data = "/data";
  char *esl_data_path = NULL;
  uint8_t *current_esl = *current_esl_data;
  size_t current_esl_size;

  if (args->variable_path != NULL)
    {
      len = strlen (args->variable_path) + strlen ((char *) update_variable) +
            strlen (esl_data);
      esl_data_path = malloc (len + 1);
      if (esl_data_path == NULL)
        return ALLOC_FAIL;

      memset (esl_data_path, 0x00, len + 1);
      len = 0;
      memcpy (esl_data_path + len, args->variable_path, strlen (args->variable_path));
      len += strlen (args->variable_path);
      memcpy (esl_data_path + len, update_variable, strlen ((char *) update_variable));
      len += strlen ((char *) update_variable);
      memcpy (esl_data_path + len, esl_data, strlen (esl_data));

      if (is_file (esl_data_path) == SUCCESS)
        rc = get_current_esl_data ((uint8_t *) esl_data_path, &current_esl,
                                   &current_esl_size);
      free (esl_data_path);
    }
  else
    {
      for (i = 0; i < args->current_variable_size; i += 2)
        {
          if (memcmp (args->current_variable[i], update_variable,
                      strlen ((char *) update_variable)) == 0)
            {
              rc = get_current_esl_data ((uint8_t *) args->current_variable[i + 1],
                                         &current_esl, &current_esl_size);
              if (rc != SUCCESS)
                return rc;
              break;
            }
        }
    }

  *current_esl_data = current_esl;
  *current_esl_data_size = current_esl_size;

  return rc;
}

/*
 * verify the all the update variables
 */
static int
verify_update_variable (const struct verify_args *args, const uint8_t *pk_esl_data,
                        const size_t pk_esl_data_size, const uint8_t *kek_esl_data,
                        const size_t kek_esl_data_size, bool flag)
{
  int i = 0, rc = SUCCESS;
  uint8_t *auth_data = NULL, *current_esl_data = NULL, *new_esl_data = NULL;
  size_t auth_data_size = 0, current_esl_data_size = 0, new_esl_data_size = 0;
  bool append_update;

  for (i = 0; i < args->update_variable_size; i += 2)
    {
      if ((memcmp (args->update_variable[i], PK_VARIABLE, PK_LEN) == 0 ||
          memcmp (args->update_variable[i], KEK_VARIABLE, KEK_LEN) == 0) && flag)
        continue;

      rc = get_auth_data ((uint8_t *) args->update_variable[i + 1],
                          &auth_data, &auth_data_size, &append_update);
      if (rc != SUCCESS)
        continue;

      rc = get_current_esl (args, (uint8_t *) args->update_variable[i],
                            &current_esl_data, &current_esl_data_size);
      if (rc == SUCCESS)
        rc = update_variable ((uint8_t *) args->update_variable[i], auth_data + APPEND_HEADER_LEN,
                              auth_data_size - APPEND_HEADER_LEN, current_esl_data,
                              current_esl_data_size, pk_esl_data,
                              pk_esl_data_size, kek_esl_data, kek_esl_data_size,
                              append_update, &new_esl_data, &new_esl_data_size);

      if ((rc == SUCCESS || rc == DELETE_EVERYTHING)  &&
          args->write_flag && args->variable_path != NULL)
        {
          rc = write_to_variable (args->variable_path, args->update_variable[i],
                                  auth_data, auth_data_size);
          if (rc != SUCCESS)
            prlog (PR_ERR, "ERROR: issue writing to file: %s\n", strerror (errno));
        }

      if (auth_data != NULL)
        free (auth_data);

      auth_data = NULL;
      if (rc != SUCCESS)
        break;
    }

  return rc;
}

/*
 * extract the PK and KEK variable from path variables
 */
static int
get_pk_and_kek_from_path_var (const struct verify_args *args, uint8_t **pk_esl_data,
                              size_t *pk_esl_data_size, uint8_t **kek_esl_data,
                              size_t *kek_esl_data_size)
{
  int rc = SUCCESS;
  size_t len = 0;
  char *esl_data = "/data";
  char *esl_data_path = NULL;

  if (args->variable_path != NULL)
    {
      len = strlen (args->variable_path) + PK_LEN + strlen (esl_data);
      esl_data_path = malloc (len + 1);
      if (esl_data_path == NULL)
        return ALLOC_FAIL;

      memset (esl_data_path, 0x00, len + 1);
      len = 0;
      memcpy (esl_data_path + len, args->variable_path, strlen (args->variable_path));
      len += strlen (args->variable_path);
      memcpy (esl_data_path + len, PK_VARIABLE, PK_LEN);
      len += PK_LEN;
      memcpy (esl_data_path + len, esl_data, strlen (esl_data));

      if (is_file (esl_data_path) == SUCCESS)
        rc = get_current_esl_data ((uint8_t *) esl_data_path, pk_esl_data, pk_esl_data_size);

      free (esl_data_path);
      len = strlen (args->variable_path) + KEK_LEN + strlen (esl_data);
      esl_data_path = malloc (len + 1);
      if (esl_data_path == NULL)
        return ALLOC_FAIL;

      memset (esl_data_path, 0x00, len + 1);
      len = 0;
      memcpy (esl_data_path + len, args->variable_path, strlen (args->variable_path));
      len += strlen (args->variable_path);
      memcpy (esl_data_path + len, KEK_VARIABLE, KEK_LEN);
      len += KEK_LEN;
      memcpy (esl_data_path + len, esl_data, strlen (esl_data));

      if (is_file (esl_data_path) == SUCCESS)
        rc = get_current_esl_data ((uint8_t *) esl_data_path, kek_esl_data, kek_esl_data_size);

      free (esl_data_path);
    }

  return rc;
}

/*
 * extract the PK and KEK variable from update variables
 */
static int
get_pk_and_kek_from_update_var (const struct verify_args *args, uint8_t **pk_esl_data,
                                size_t *pk_esl_data_size, uint8_t **kek_esl_data,
                                size_t *kek_esl_data_size)
{
  int i = 0, rc = SUCCESS;
  uint8_t *current_esl_data = NULL, *auth_data = NULL;
  size_t current_esl_data_size = 0, auth_data_size = 0;
  bool append_update;

  for (i = 0; i < args->update_variable_size; i += 2)
    {
      auth_data = NULL;
      if (memcmp (args->update_variable[i], PK_VARIABLE,
                  strlen (args->update_variable[i])) == 0 &&
          (*pk_esl_data == NULL && *pk_esl_data_size == 0))
        {
          rc = get_auth_data ((uint8_t *) args->update_variable[i + 1],
                              &auth_data, &auth_data_size, &append_update);
          if (rc == SUCCESS)
            {
              rc = update_variable ((uint8_t *) args->update_variable[i],
                                    auth_data + APPEND_HEADER_LEN,
                                    auth_data_size - APPEND_HEADER_LEN,
                                    current_esl_data, current_esl_data_size, *pk_esl_data,
                                    *pk_esl_data_size, *kek_esl_data, *kek_esl_data_size,
                                    append_update, pk_esl_data, pk_esl_data_size);
              if (auth_data != NULL)
                free (auth_data);

              if (rc != SUCCESS)
                return rc;
            }
        }
      else if (memcmp (args->update_variable[i], KEK_VARIABLE,
                       strlen (args->update_variable[i])) == 0 &&
               (*kek_esl_data == NULL && *kek_esl_data_size == 0))
        {
          rc = get_auth_data ((uint8_t *) args->update_variable[i + 1],
                              &auth_data, &auth_data_size, &append_update);
          if (rc == SUCCESS)
            {
              rc = update_variable ((uint8_t *) args->update_variable[i],
                                    auth_data + APPEND_HEADER_LEN,
                                    auth_data_size - APPEND_HEADER_LEN,
                                    current_esl_data, current_esl_data_size, *pk_esl_data,
                                    *pk_esl_data_size, *kek_esl_data, *kek_esl_data_size,
                                    append_update, kek_esl_data, kek_esl_data_size);
              if (auth_data != NULL)
                free (auth_data);

              if (rc != SUCCESS)
                return rc;
            }
        }

      if (*pk_esl_data != NULL && *kek_esl_data != NULL)
        break;
    }

  return rc;
}

/*
 * extract the PK and KEK from update or current or path variables and
 * verify the all variables using PK or KEK
 */
int
verify_variables (struct verify_args *args)
{
  int rc = SUCCESS, i = 0;
  uint8_t *pk_esl_data = NULL, *kek_esl_data = NULL;
  size_t pk_esl_data_size = 0, kek_esl_data_size = 0;
  bool flag = false;

  if (args->variable_path != NULL)
    rc = get_pk_and_kek_from_path_var (args, &pk_esl_data, &pk_esl_data_size,
                                       &kek_esl_data, &kek_esl_data_size);
  else if (args->current_variable_size > 0)
    {
      for (i = 0; i < args->current_variable_size; i += 2)
        {
          if (memcmp (args->current_variable[i], PK_VARIABLE,
                      strlen (args->current_variable[i])) == 0)
            rc = get_current_esl_data ((uint8_t *) args->current_variable[i + 1],
                                       &pk_esl_data, &pk_esl_data_size);
          else if (memcmp (args->current_variable[i], KEK_VARIABLE,
                           strlen (args->current_variable[i])) == 0)
            rc = get_current_esl_data ((uint8_t *) args->current_variable[i + 1],
                                       &kek_esl_data, &kek_esl_data_size);
          if (pk_esl_data != NULL && kek_esl_data != NULL)
            break;
        }
    }
  else if (args->update_variable_size > 0)
    {
      rc = get_pk_and_kek_from_update_var (args, &pk_esl_data, &pk_esl_data_size,
                                           &kek_esl_data, &kek_esl_data_size);
      flag = true;
    }

  if (rc == SUCCESS)
    {
      rc = verify_update_variable (args, pk_esl_data, pk_esl_data_size,
                                   kek_esl_data, kek_esl_data_size, flag);
    }

  if (pk_esl_data != NULL)
    free (pk_esl_data);

  if (kek_esl_data != NULL)
    free (kek_esl_data);

  return rc;
}

/*
 * extract the variables and its auth file or ESL file from agruments
 */
int
parse_variable_arguments (struct argp_state *state, const char ***variables, int *variable_size)
{
  int current = state->next - 1;
  const char **variable;

  while (state->next != state->argc && state->argv[state->next][0] != '-')
    state->next++;

  *variable_size = (state->next - current);
  variable = malloc (sizeof (char *) * (*variable_size));
  if (variable == NULL)
    {
      prlog (PR_ERR, "ERROR: failed to allocate memory\n");
      return ALLOC_FAIL;
    }

  memcpy (variable, &state->argv[current], ((*variable_size) * sizeof (char *)));
  *variables = variable;

  return SUCCESS;
}

/*
 * validating the variables agruments
 */
int
validate_variables_arguments (struct verify_args *args)
{
  int i = 0;

  if (args->update_variable_size == 0 || args->update_variable_size <= 1)
    {
      prlog (PR_ERR,
             "ERROR: needs the update variable and respective auth files\n"
             " Example: -u <var_name 1> <var_auth_file 1>...<var_name N> "
             "<var_auth_file N>\n");
      return ARG_PARSE_FAIL;
    }
  else if (args->update_variable_size % 2)
    {
      prlog (PR_ERR, "ERROR: update variable argument should be like -u "
                     "<var_name 1> <var_auth_file 1>"
                     "...<var_name N> <var_auth_file N>\n");
      return ARG_PARSE_FAIL;
    }

  if (args->current_variable_size != 0)
    {
      if (args->write_flag)
        {
          prlog (PR_ERR, "ERROR: cannot update files if current variable "
                         "files are given. remove -w\n");
          return ARG_PARSE_FAIL;
        }
      else if (args->current_variable_size % 2)
        {
          prlog (PR_ERR, "ERROR: current variable argument should be like -c "
                         "<var_name 1> <var_ESL_file 1>"
                         "...<var_name N> <var_ESL_file N>\n");
          return ARG_PARSE_FAIL;
        }
    }

  for (i = 0; i < args->update_variable_size; i += 2)
    {
      if (!is_secure_boot_variable (args->update_variable[i]))
			  prlog(PR_WARNING, "WARNING!! %s is an arbitrary variable name\n",
              args->update_variable[i]);
    }

  for (i = 0; i < args->current_variable_size; i += 2)
    {
      if (!is_secure_boot_variable (args->current_variable[i]))
			  prlog(PR_WARNING, "WARNING!! %s is an arbitrary variable name\n",
              args->current_variable[i]);
    }

  return SUCCESS;
}
