void __fastcall sub_559EBC003D50(Node *a1)
{
  size_t content; // rbx

  if ( (__int64)a1->fd->content <= 254 )
  {
    content = a1->fd->fd->fd->fd->fd->fd->fd->content;
    **(_BYTE **)(content + 8 * a1->fd->fd->content) ^= byte_559EBC20B060[(unsigned __int8)a1->fd->content];
    free((void *)a1->content);
  }
  else
  {
    a1->fd->content -= 255LL;
    a1->fd->content = ((__int64)a1->fd->content >> 8) + (unsigned __int8)a1->fd->content;
    free(a1);
  }
}