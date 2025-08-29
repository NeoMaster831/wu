void __fastcall sub_559EBC004F89(Node *a1)
{
  signed __int64 v1; // rax

  v1 = sys_sendfile(
         a1->fd->fd->content,
         a1->fd->content,
         (off_t *)&a1->bk,
         *(_QWORD *)(a1->fd->fd->fd->fd->fd->fd->content + 48));
}