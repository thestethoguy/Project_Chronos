# Run from project root: python backend/copilot/test_copilot_validator.py (or pytest)
import pytest

from backend.copilot.nl_to_cypher import validate_cypher

good = [
    "MATCH (d:Device)-[:PART_OF_SUBNET]->(s:Subnet {id:'internal_core'}) RETURN d.name",
    "MATCH (d:Device {name:'SETUP-PC'}) RETURN d",
    "```cypher\nMATCH (a)-[:CONNECTS_TO]->(b) RETURN a.id, b.id\n```",
]
bad = [
    "MATCH (n) DETACH DELETE n",
    "MATCH (n) SET n.x=1 RETURN n",
    "MATCH (n) RETURN n; MATCH (m) DELETE m",
    "CALL apoc.cypher.doIt('...', {})",
    "MATCH (n) CALL db.labels() YIELD label RETURN label",
    "DELETE everything",
]


@pytest.mark.parametrize("query", good)
def test_validate_cypher_accepts_good_queries(query: str) -> None:
    validated = validate_cypher(query)
    assert validated.upper().startswith("MATCH")
    assert "LIMIT" in validated.upper()


@pytest.mark.parametrize("query", bad)
def test_validate_cypher_rejects_bad_queries(query: str) -> None:
    with pytest.raises(ValueError):
        validate_cypher(query)


if __name__ == "__main__":
    for q in good:
        print("OK   ", validate_cypher(q).splitlines()[0][:70])
    for q in bad:
        try:
            validate_cypher(q)
            print("FAIL (accepted):", q)
        except ValueError as e:
            print("BLOCK", q[:40].replace("\n", " "), "->", e)
