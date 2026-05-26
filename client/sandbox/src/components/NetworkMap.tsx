import React, { useState, useMemo, useRef } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape from 'cytoscape';
import { useSimulation } from '../context/SimulationContext';
import { DeviceNode } from '../types';
import NodeDetailsPanel from './NodeDetailsPanel';

export default function NetworkMap() {
  const { nodes, edges } = useSimulation();
  const [selectedNode, setSelectedNode] = useState<DeviceNode | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const elements = useMemo(() => {
    const cyNodes = nodes.map(n => ({
      data: { 
        id: n.id, 
        label: n.hostname,
        os: n.os,
        status: n.status
      },
      classes: `status-${n.status.toLowerCase()} ${selectedNode?.id === n.id ? 'selected' : ''}`
    }));

    const cyEdges = edges.map(e => {
      // If either source or target is RED, edge becomes active
      const srcNode = nodes.find(n => n.id === e.source);
      const tgtNode = nodes.find(n => n.id === e.target);
      const isAttacking = srcNode?.status === 'RED' && tgtNode?.status === 'RED';
      
      return {
        data: { id: e.id, source: e.source, target: e.target },
        classes: isAttacking ? 'edge-active' : 'edge-normal'
      };
    });

    return [...cyNodes, ...cyEdges];
  }, [nodes, edges, selectedNode]);

  const layout = useMemo(() => ({
    name: 'cose',
    idealEdgeLength: 100,
    nodeOverlap: 20,
    refresh: 20,
    fit: true,
    padding: 30,
    randomize: false,
    componentSpacing: 100,
    nodeRepulsion: 400000,
    edgeElasticity: 100,
    nestingFactor: 5,
  }), []);

  const style = [
    {
      selector: 'node',
      style: {
        'label': 'data(label)',
        'color': '#c9d1d9',
        'font-size': '12px',
        'font-family': 'monospace',
        'text-valign': 'bottom',
        'text-margin-y': 8,
        'background-color': '#161b22', 
        'border-width': 2,
        'border-color': '#30363d', 
        'width': 40,
        'height': 40,
      }
    },
    {
      selector: 'node.status-green',
      style: {
        'border-color': '#00ff88', 
        'background-color': '#00ff88', 
        'background-opacity': 0.1,
      }
    },
    {
      selector: 'node.status-yellow',
      style: {
        'border-color': '#ffaa00', 
        'background-color': '#ffaa00',
        'background-opacity': 0.1,
      }
    },
    {
      selector: 'node.status-red',
      style: {
        'border-color': '#ff3355', 
        'background-color': '#ff3355',
        'background-opacity': 0.2,
      }
    },
    {
      selector: 'node.status-grey',
      style: {
        'border-color': '#30363d', 
        'background-color': '#0d1117', 
        'border-style': 'dashed',
      }
    },
    {
      selector: 'node.selected',
      style: {
        'border-width': 4,
        'border-color': '#00d4ff', 
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': '#30363d',
        'curve-style': 'bezier',
        'target-arrow-shape': 'triangle',
        'target-arrow-color': '#30363d',
        'opacity': 0.5,
      }
    },
    {
      selector: 'edge.edge-active',
      style: {
        'line-color': '#ff3355',
        'target-arrow-color': '#ff3355',
        'width': 4,
        'opacity': 0.9,
        'line-style': 'dashed',
      }
    }
  ];

  return (
    <div className="relative w-full h-full">
      <CytoscapeComponent
        elements={elements}
        layout={layout}
        stylesheet={style as unknown as cytoscape.StylesheetCSS[]}
        style={{ width: '100%', height: '100%' }}
        cy={(cy: cytoscape.Core) => {
          cyRef.current = cy;
          cy.on('tap', 'node', (evt: cytoscape.EventObject) => {
            const nodeId = evt.target.id();
            const node = nodes.find((n: DeviceNode) => n.id === nodeId);
            if (node) setSelectedNode(node);
          });
          cy.on('tap', (evt: cytoscape.EventObject) => {
            if (evt.target === cy) {
              setSelectedNode(null);
            }
          });
        }}
        minZoom={0.5}
        maxZoom={2}
      />

      {/* Pulsing overlay for red nodes (since Cytoscape keyframe animations are limited) */}
      {nodes.filter(n => n.status === 'RED').length > 0 && (
        <div className="absolute inset-0 pointer-events-none animate-pulse-slow shadow-[inset_0_0_100px_rgba(255,51,85,0.2)]"></div>
      )}

      {selectedNode && (
        <NodeDetailsPanel 
          node={selectedNode} 
          onClose={() => setSelectedNode(null)} 
        />
      )}
    </div>
  );
}
