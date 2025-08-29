void __fastcall sub_559EBC00544B(Node *a1)
{
  if ( (a1->fd->content & 0x8000000000000000LL) == 0LL )
  {
    a1->fd->fd->fd->fd->fd->fd->fd->fd->content = (size_t)&off_559EBC20CC00;
    a1->content = (signed __int64)a1->content >> 8;
    free(&off_559EBC20C540);
  }
  else
  {
    free(&off_559EBC20BC70);
  }
}