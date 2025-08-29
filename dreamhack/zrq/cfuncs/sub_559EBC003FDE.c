void __fastcall sub_559EBC003FDE(Node *a1)
{
  Node *fd; // rbx

  if ( a1->content == 16 )
  {
    fd = a1->fd->fd->fd;
    fd->content = 0xA2E656E6F44LL;
    free(fd);
  }
  else
  {
    a1->content = (signed __int64)(a1->content + 5) % 21;
    a1->fd->content = a1->content;
  }
}