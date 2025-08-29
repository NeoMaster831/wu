void __fastcall sub_559EBC004402(Node *a1)
{
  _UNKNOWN ******v1; // rax

  if ( (a1->content & 0x8000000000000000LL) == 0LL )
    v1 = (_UNKNOWN ******)&off_559EBC20BA00;
  else
    v1 = &off_559EBC20C840;
  free(v1);
  a1->fd->fd->fd->content = a1->fd->fd->fd->fd->fd->fd->content + 18;
}