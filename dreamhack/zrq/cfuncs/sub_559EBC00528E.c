void __fastcall sub_559EBC00528E(Node *a1)
{
  if ( sprintf((char *)a1->fd->fd->fd->fd->fd->content, "%s", (const char *)a1->fd->fd->fd->content) == 254 )
  {
    *(_BYTE *)a1->fd->fd->fd->content = 0;
    free(&off_559EBC20B910);
  }
  else
  {
    free(&off_559EBC20B8B0);
  }
}