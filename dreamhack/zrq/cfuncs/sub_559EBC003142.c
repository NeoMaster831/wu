void __fastcall sub_559EBC003142(Node *a1)
{
  if ( (a1->fd->fd->fd->content & 0x8000000000000000LL) == 0LL )
  {
    a1->fd->fd->content = (size_t)a1->fd;
    free(&off_559EBC20C540);
  }
  else
  {
    free(&off_559EBC20BC70);
  }
}