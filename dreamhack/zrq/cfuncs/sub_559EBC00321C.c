void __fastcall sub_559EBC00321C(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd;
  if ( *(_BYTE *)(a1->fd->content + a1->fd->fd->fd->fd->fd->fd->fd->content - 1) != (unsigned __int8)a1->content )
  {
    free(a1);
    --fd->content;
  }
}