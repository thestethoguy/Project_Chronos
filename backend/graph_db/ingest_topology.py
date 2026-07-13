import json
from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
USER = "neo4j"
PASSWORD = "password123"

def load_network_data():
    with open("network_topology.json", "r") as file:
        data = json.load(file)
    
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    
    with driver.session() as session:
        # Wipe old experimental graph entries cleanly to avoid node mixing
        session.run("MATCH (n) DETACH DELETE n")
        
        # Inject Subnet zones
        for subnet in data["subnets"]:
            session.run(
                """
                MERGE (s:Subnet {id: $id})
                SET s.name = $name, s.scope = $scope
                """,
                id=subnet["id"], name=subnet["name"], scope=subnet["scope"]
            )
        
        # Inject our expanded 20-node tracking matrix
        for node in data["nodes"]:
            session.run(
                """
                MERGE (n:Device {id: $id})
                SET n.name = $name, n.ip = $ip, n.ports = $ports, n.os = $os, n.cves = $cves
                WITH n, $subnet_id AS sub_id
                MATCH (s:Subnet {id: sub_id})
                MERGE (n)-[:PART_OF_SUBNET]->(s)
                """,
                id=node["id"], name=node["name"], ip=node["ip"],
                ports=node["ports"], os=node["os"], cves=node["cves"], subnet_id=node["subnet"]
            )
            
        # Wire direct hardware communications links (Attack vectors)
        for rel in data["relationships"]:
            session.run(
                """
                MATCH (src:Device {id: $source})
                MATCH (tgt:Device {id: $target})
                MERGE (src)-[:CONNECTS_TO {type: $type}]->(tgt)
                """,
                source=rel["source"], target=rel["target"], type=rel["type"]
            )
            
    driver.close()
    print("Successfully populated scaled 20-node Digital Twin infrastructure array!")

if __name__ == "__main__":
    load_network_data()