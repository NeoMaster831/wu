void __fastcall sub_559EBC004F12(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd;
  if ( (signed __int64)a1->content < (signed __int64)fd->fd->fd->content )
  {
    a1->content += 21LL;
    free(&off_559EBC20C720);
  }
  fd->content += 120LL;
  fd->fd->content += 48LL;
}