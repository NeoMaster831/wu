void __fastcall sub_559EBC004E3E(Node *a1)
{
  _BYTE *content; // rbx

  a1->fd->content = (size_t)malloc(0x110u);
  content = (_BYTE *)a1->fd->fd->fd->fd->fd->fd->content;
  *(_QWORD *)(a1->fd->content + 32) = content[1] & 0xF | (unsigned int)(unsigned __int8)(16 * *content);
}