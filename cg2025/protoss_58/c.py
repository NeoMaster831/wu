from solver_pb2 import *
from solver_pb2_grpc import *

def solve():
    channel = grpc.insecure_channel('3.37.15.100:50051')
    stub = SecretServiceStub(channel)
    response = stub.Flag(FlagRequest(token='66Vabd1YEadb2WtMbXet.5f7ef65b19dabcbd', hidden='My_1ife_F0r_Aiur!!'))
    print(response)

if __name__ == '__main__':
    solve()
