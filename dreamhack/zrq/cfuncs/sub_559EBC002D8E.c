void __fastcall sub_559EBC002D8E(Node *a1)
{
  _UNKNOWN ******content; // rax

  if ( sys_chdir((const char *)&a1->fd->content) )
    content = &off_559EBC20C840;
  else
    content = (_UNKNOWN ******)a1->content;
  free(content);
}