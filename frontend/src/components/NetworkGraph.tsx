import { useMemo } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type { Core } from "cytoscape";
import type {
  NetworkEdge,
  NetworkNode,
} from "../types/simulation";

interface NetworkGraphProps {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  selectedNodeId?: string;
  onNodeSelect: (nodeId: string) => void;
}

export function NetworkGraph({
  nodes,
  edges,
  selectedNodeId,
  onNodeSelect,
}: NetworkGraphProps) {
  const elements = useMemo(
    () => [
      ...nodes.map((node) => ({
        data: {
          id: node.id,
          label: node.label,
          status: node.status,
          type: node.type,
          critical: node.isCriticalService
            ? "true"
            : "false",
        },
        selected:
          node.id === selectedNodeId,
      })),

      ...edges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          active: edge.active
            ? "true"
            : "false",
        },
      })),
    ],
    [
      nodes,
      edges,
      selectedNodeId,
    ]
  );

  return (
    <section className="panel graph-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">
            LIVE TOPOLOGY
          </p>

          <h2>
            Infrastructure Digital Twin
          </h2>
        </div>

        <div className="legend">
          <span>
            <i className="legend-default" />
            Normal
          </span>

          <span>
            <i className="legend-compromised" />
            Compromised
          </span>

          <span>
            <i className="legend-isolated" />
            Isolated
          </span>

          <span>
            <i className="legend-attack-path" />
            Attack Path
          </span>
        </div>
      </div>

      <div className="graph-container">
        <CytoscapeComponent
          elements={elements}
          layout={{
            name: "breadthfirst",
            directed: true,
            padding: 40,
            spacingFactor: 1.5,
            animate: true,
          }}
          style={{
            width: "100%",
            height: "100%",
          }}
       cy={(cy: Core) => {
  cy.removeAllListeners();

  cy.on("tap", (event) => {
    const target = event.target;

    if (target && target.isNode?.()) {
      onNodeSelect(target.id());
    }
  });
}}
          stylesheet={[
            {
              selector: "node",
              style: {
                "background-color":
                  "#102b47",

                "border-color":
                  "#63adff",

                "border-width": 3,

                width: 62,
                height: 62,

                color: "#edf5ff",

                label:
                  "data(label)",

                "font-size": 11,

                "font-weight": 700,

                "text-valign":
                  "bottom",

                "text-margin-y": 10,

                "text-outline-color":
                  "#07111f",

                "text-outline-width":
                  2,
              },
            },

            {
              selector:
                'node[critical = "true"]',

              style: {
                "border-color":
                  "#ffbd5e",

                "border-width": 4,
              },
            },

            {
  selector: 'node[status = "compromised"]',
  style: {
    "background-color": "#651b2a",
    "border-color": "#ff5c74",
    "border-width": 5,
  },
},
            {
              selector:
                'node[status = "isolated"]',

              style: {
                "background-color":
                  "#123451",

                "border-color":
                  "#53d6ff",

                "border-style":
                  "dashed",

                "border-width": 5,

                opacity: 0.82,
              },
            },

            {
              selector:
                "node:selected",

              style: {
                "overlay-color":
                  "#ffffff",

                "overlay-opacity":
                  0.12,

                "overlay-padding":
                  12,

                "border-color":
                  "#ffffff",
              },
            },

            {
              selector: "edge",

              style: {
                width: 2,

                "line-color":
                  "#2a5375",

                "target-arrow-color":
                  "#2a5375",

                "target-arrow-shape":
                  "triangle",

                "curve-style":
                  "bezier",

                opacity: 0.8,
              },
            },

           {
  selector: 'edge[active = "true"]',
  style: {
    width: 6,

    "line-color": "#ff5c74",
    "target-arrow-color": "#ff5c74",

    opacity: 1,
  },
},
          ]}
        />
      </div>
    </section>
  );
}