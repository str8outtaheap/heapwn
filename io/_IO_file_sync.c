int
_IO_new_file_sync (_IO_FILE *fp)
{
  _IO_ssize_t delta;
  int retval = 0;

  /*    char* ptr = cur_ptr(); */
  if (fp->_IO_write_ptr > fp->_IO_write_base)
    if (_IO_do_flush(fp)) return EOF;
  delta = fp->_IO_read_ptr - fp->_IO_read_end;
  if (delta != 0)
    {
#ifdef TODO
      if (_IO_in_backup (fp))
	delta -= eGptr () - Gbase ();
#endif
      _IO_off64_t new_pos = _IO_SYSSEEK (fp, delta, 1);
      if (new_pos != (_IO_off64_t) EOF)
	fp->_IO_read_end = fp->_IO_read_ptr;
#ifdef ESPIPE
      else if (errno == ESPIPE)
	; /* Ignore error from unseekable devices. */
#endif
      else
	retval = EOF;
    }
  if (retval != EOF)
    fp->_offset = _IO_pos_BAD;
  /* FIXME: Cleanup - can this be shared? */
  /*    setg(base(), ptr, ptr); */
  return retval;
}
libc_hidden_ver (_IO_new_file_sync, _IO_file_sync)
