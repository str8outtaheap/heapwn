char *
_IO_fgets (buf, n, fp)
     char *buf;
     int n;
     _IO_FILE *fp;
{
  _IO_size_t count;
  char *result;
  int old_error;
  CHECK_FILE (fp, NULL);
  if (n <= 0)
    return NULL;
  if (__builtin_expect (n == 1, 0))
    {
      /* Another irregular case: since we have to store a NUL byte and
	 there is only room for exactly one byte, we don't have to
	 read anything.  */
      buf[0] = '\0';
      return buf;
    }
  _IO_acquire_lock (fp);
  /* This is very tricky since a file descriptor may be in the
     non-blocking mode. The error flag doesn't mean much in this
     case. We return an error only when there is a new error. */
  old_error = fp->_IO_file_flags & _IO_ERR_SEEN;
  fp->_IO_file_flags &= ~_IO_ERR_SEEN;
  count = _IO_getline (fp, buf, n - 1, '\n', 1);
  /* If we read in some bytes and errno is EAGAIN, that error will
     be reported for next read. */
  if (count == 0 || ((fp->_IO_file_flags & _IO_ERR_SEEN)
		     && errno != EAGAIN))
    result = NULL;
  else
    {
      buf[count] = '\0';
      result = buf;
    }
  fp->_IO_file_flags |= old_error;
  _IO_release_lock (fp);
  return result;
}
