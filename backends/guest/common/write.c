/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022-2023 IBM Corp.
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "prlog.h"
#include "err.h"
#include "generic.h"
#include "common/validate.h"
#include "common/write.h"

/*
 * updates a secure variable by writing data in buffer to the
 * <path>/<variable name>/update
 *
 * @param path, path to sec vars
 * @param variable_name, one of Guest secure boot variable
 * @param buffer , auth data
 * @param buffer_size , size of auth data
 * @return whatever returned by writeData, SUCCESS or errno
 */
int
write_to_variable (const char *path, const char *variable_name, const uint8_t *buffer, const size_t buffer_size)
{
  int len, rc;
  char *file_name = "/update";
  char *variable_path = NULL;

  len = strlen (path) + strlen (variable_name) + strlen (file_name);
  variable_path = malloc (len + 1);
  if (variable_path == NULL)
    {
      prlog (PR_ERR, "ERROR: failed to allocate memory\n");
      return ALLOC_FAIL;
    }

  memset (variable_path, 0x00, len + 1);
  len = 0;
  memcpy (variable_path + len, path, strlen (path));
  len += strlen (path);
  memcpy (variable_path + len, variable_name, strlen (variable_name));
  len += strlen (variable_name);
  memcpy (variable_path + len, file_name, strlen (file_name));

  rc = write_data_to_file (variable_path, (const char *) buffer, buffer_size);
  free (variable_path);

  return rc;
}

/*
 * ensures updating variable is a valid variable, creates full path to
 * .../update file, verifies auth file is valid
 *
 * @param variable_name, Guest secure boot variable name
 * @param auth_file, auth file name
 * @param path,  path to Guest secure boot variables directory
 * @param force, 1 for no validation of auth, 0 for validate
 * @return error if variable given is unknown, or issue validating or writing
 */
int
write_variable (const uint8_t *variable_name, const uint8_t *auth_file, const uint8_t *path, int force)
{
  int rc;
  uint8_t *buffer = NULL;
  size_t buffer_size;

  if (!path)
    {
      path = (uint8_t *) SECVARPATH;
    }

  buffer = (uint8_t *) get_data_from_file ((char *) auth_file, SIZE_MAX, &buffer_size);
  if (buffer == NULL)
    return INVALID_FILE;

  if (!force)
    {
      rc = validate_auth (buffer, buffer_size);
      if (rc != SUCCESS)
        {
          prlog (PR_ERR,
                 "ERROR: validating signed auth file failed, not updating\n");
          free (buffer);
          return rc;
        }
    }

  rc = write_to_variable ((char *) path, (char *) variable_name, buffer, buffer_size);
  if (rc != SUCCESS)
    prlog (PR_ERR, "ERROR: issue writing to file: %s\n", strerror (errno));

  free (buffer);

  return rc;
}
