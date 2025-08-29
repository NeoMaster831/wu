void __fastcall sub_559EBC002AB7(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd->fd->fd->fd;
  if ( sys_read(fd->fd->content, (char *)&fd->fd->fd->fd->content, 1u) != 1 )
  {
    *(_BYTE *)fd->content = 0;
    free(&off_559EBC20C1E0);
  }
}