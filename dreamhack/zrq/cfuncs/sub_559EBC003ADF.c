void __fastcall sub_559EBC003ADF(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd->fd->fd;
  if ( fd->content == a1->fd->content + a1->content )
  {
    fd->content -= a1->content;
    free(&off_559EBC20BC40);
  }
  else
  {
    a1->fd->fd->content = (size_t)a1;
    free((char *)&unk_559EBC208020 + 48 * *(unsigned __int8 *)(a1->content + a1->fd->content) + 16);
    ++a1->content;
  }
}