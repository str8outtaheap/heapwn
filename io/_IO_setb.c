void
_IO_setb (_IO_FILE *f, char *b, char *eb, int a)
{
  if (f->_IO_buf_base && !(f->_flags & _IO_USER_BUF))
    free (f->_IO_buf_base);
  f->_IO_buf_base = b;
  f->_IO_buf_end = eb;
  if (a)
    f->_flags &= ~_IO_USER_BUF;
  else
    f->_flags |= _IO_USER_BUF;
}
libc_hidden_def (_IO_setb)
