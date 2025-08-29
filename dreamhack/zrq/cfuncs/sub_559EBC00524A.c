void __fastcall sub_559EBC00524A(Node *a1)
{
  qmemcpy((void *)a1->content, (const void *)a1->fd->fd->content, 0x110u);
  free(&off_559EBC20BC70);
}