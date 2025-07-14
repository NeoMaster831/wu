import math
from typing import Tuple, List

def dot(u: List[float], v: List[float]) -> float:
    return sum(ui*vi for ui, vi in zip(u, v))

def norm(v: List[float]) -> float:
    return math.sqrt(dot(v, v))

def normalize(v: List[float]) -> List[float]:
    n = norm(v)
    return [vi / n for vi in v]

def e_components_4d(
    p0: Tuple[int,int,int,int],
    p1: Tuple[int,int,int,int],
    p2: Tuple[int,int,int,int]
) -> Tuple[Tuple[float,float,float,float],
           Tuple[float,float,float,float],
           Tuple[float,float,float,float]]:
    # Convert to float lists
    v0 = [float(x) for x in p0]
    v1 = [float(x) for x in p1]
    v2 = [float(x) for x in p2]

    # e1 = v0 / ||v0||
    e1 = normalize(v0)

    # u1 = v1 - <v1,e1> e1
    proj1 = dot(v1, e1)
    u1 = [v1[i] - proj1 * e1[i] for i in range(4)]
    # e2 = u1 / ||u1||
    e2 = normalize(u1)

    # u2 = v2 - <v2,e1> e1 - <v2,e2> e2
    proj2_e1 = dot(v2, e1)
    proj2_e2 = dot(v2, e2)
    u2 = [v2[i] - proj2_e1 * e1[i] - proj2_e2 * e2[i] for i in range(4)]
    # e3 = u2 / ||u2||
    e3 = normalize(u2)

    return (tuple(e1), tuple(e2), tuple(e3))