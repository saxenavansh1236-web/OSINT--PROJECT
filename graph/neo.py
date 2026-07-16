from neo4j import GraphDatabase

driver=""

GraphDatabase.driver(

"bolt://localhost:7687",

auth=(

"neo4j",

"password"

)

)

def save(domain):

    with driver.session() as s:

        s.run(

"""
CREATE(n:Domain{
name:$d
})
""",

d=domain
)