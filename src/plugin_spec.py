[
  {
    "node": {
      "node_name": "product_profile",
      "node_route": "node_001"
    }
  },
  {
    "node": {
      "node_name": "hitl_approval",
      "node_route": "node_002"
    }
  },
  {
    "node": {
      "node_name": "threat_intelligence",
      "node_route": "node_004"
    }
  },
  {
    "node": {
      "node_name": "vendor_analysis",
      "node_route": "node_005"
    }
  },
  {
    "node": {
      "node_name": "compliance",
      "node_route": "node_006"
    }
  },
  {
    "node": {
      "node_name": "cve_analysis",
      "node_route": "node_007"
    }
  },
  {
    "node": {
      "node_name": "product_risk",
      "node_route": "node_008"
    }
  },
  {
    "node": {
      "node_name": "hitl_approval",
      "node_route": "node_009"
    }
  },
  {
    "edge": {
      "edge_type": "fan_out",
      "source": "node_002",
      "targets": [
        "node_007",
        "node_006",
        "node_005",
        "node_004"
      ]
    }
  },
  {
    "edge": {
      "edge_type": "fan_in",
      "sources": [
        "node_004",
        "node_005",
        "node_006",
        "node_007"
      ],
      "target": "node_008"
    }
  },
  {
    "edge": {
      "edge_type": "next",
      "source": "node_001",
      "target": "node_002"
    }
  },
  {
    "edge": {
      "edge_type": "next",
      "source": "node_008",
      "target": "node_009"
    }
  }
]