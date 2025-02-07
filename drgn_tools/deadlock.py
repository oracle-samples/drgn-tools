import argparse

from drgn import Object
from drgn import Program

from drgn_tools.corelens import CorelensModule
from drgn_tools.lock import scan_mutex_lock

class DependencyGraph:

    class Node:
        def __init__(self, object: Object) :
            self.name: str = object.type_.type_name() # TypeName of Object inside Node
            self.address: int = object.value_() # Memory address of Object in host RAM
            self.object: Object = object # The object itself
            self.depends_on: list[__class__] = []


        def __hash__(self):
            # Using name (example : struct task_struct") and address as unique 
            # Will be useful in case of Objects which don't exist in memory (example : CPU) - can set address=0 and name='CPU10'
            return hash((self.name, self.address))
        
        
    def __init__(self):
        self.NodeSet: dict[tuple, self.Node] = dict()


    def insert(self, dependency: tuple) -> None:
        blocking_object: Object = dependency[0]
        dependent_objects: list[Object] = dependency[1]

        if not blocking_object:
            return 
        
        key = (blocking_object.type_.type_name(), blocking_object.value_())

        if key not in self.NodeSet:
            self.NodeSet[key] = self.Node(blocking_object)
        
        blocking_node: self.Node = self.NodeSet[key]


        for dependent_object in dependent_objects:
            if not dependent_object:
                continue

            key = (dependent_object.type_.type_name(), dependent_object.value_())

            if key not in self.NodeSet:
                self.NodeSet[key] = self.Node(dependent_object)
            
            dependent_node = self.NodeSet[key]
            dependent_node.depends_on.append(blocking_node)



    def detect_cycle(self):
        visited: set[self.Node] = set()
        path = []
        cycles = []

        def dfs(node: self.Node) -> None:
            # If the node is currently being visited (part of the current DFS path), we've found a cycle
            if node in path:
                cycle_start = path.index(node)
                cycles.append(path[cycle_start:] + [node])
                return

            # If it's fully visited, no need to process this node again
            if node in visited:
                return

            visited.add(node)
            path.append(node)

            # Recursively visit all neighboring nodes
            for neighbor in node.depends_on:
                dfs(neighbor)

            path.pop() 

        # Run DFS for all nodes in the graph
        for node in self.NodeSet.values():
            if node not in visited:  # Only visit unvisited nodes
                dfs(node)

        return cycles
    
class Deadlock(CorelensModule):

    name = "deadlock"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        pass

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        graph: DependencyGraph = DependencyGraph()

        for dependency in scan_mutex_lock(prog, stack=False):
            graph.insert(dependency)

        cycles = graph.detect_cycle()

        if not cycles:
            print("No cycle found")

        for cycle in cycles:
            print(cycle)