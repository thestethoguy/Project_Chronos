import type { SimulationData } from "../types/simulation";

export const initialMockData: SimulationData = {
  simulationId: "SIM-001",
  status: "idle",
  riskScore: 42,
  currentStep: 0,

  nodes: [
    {
      id: "internet",
      label: "Internet Gateway",
      type: "gateway",
      status: "default",

      ipAddress: "203.0.113.1",
      operatingSystem: "Network Appliance",

      softwareName: "Gateway Firmware",
      softwareVersion: "5.8.2",

      riskScore: 30,
      vulnerabilities: [],
      knownCves: [],
      openPorts: [80, 443],

      isCriticalService: false,
    },

    {
      id: "web-server",
      label: "Web Server",
      type: "server",
      status: "default",

      ipAddress: "10.0.0.10",
      operatingSystem: "Ubuntu 22.04",

      softwareName: "Apache HTTP Server",
      softwareVersion: "2.4.49",

      riskScore: 82,

      vulnerabilities: [
        "Path traversal vulnerability",
        "Weak administrator password",
      ],

      knownCves: [
        "CVE-2021-41773",
        "CVE-2021-42013",
      ],

      openPorts: [80, 443, 22],

      isCriticalService: true,
      businessService: "Customer Portal",
    },

    {
      id: "app-server",
      label: "Application Server",
      type: "server",
      status: "default",

      ipAddress: "10.0.0.20",
      operatingSystem: "Ubuntu 22.04",

      softwareName: "Node.js",
      softwareVersion: "18.16.0",

      riskScore: 67,

      vulnerabilities: [
        "Weak service-account credentials",
      ],

      knownCves: [
        "CVE-2023-30589",
      ],

      openPorts: [3000, 22],

      isCriticalService: true,
      businessService: "Application API",
    },

    {
      id: "database",
      label: "Core Database",
      type: "database",
      status: "default",

      ipAddress: "10.0.0.30",
      operatingSystem: "Linux",

      softwareName: "PostgreSQL",
      softwareVersion: "13.4",

      riskScore: 88,

      vulnerabilities: [
        "Outdated database patch",
        "Excessive database permissions",
      ],

      knownCves: [
        "CVE-2021-32029",
      ],

      openPorts: [5432],

      isCriticalService: true,
      businessService: "Customer Data Service",
    },

    {
      id: "backup",
      label: "Backup Server",
      type: "server",
      status: "default",

      ipAddress: "10.0.0.40",
      operatingSystem: "Windows Server 2019",

      softwareName: "Windows SMB",
      softwareVersion: "3.1.1",

      riskScore: 48,

      vulnerabilities: [
        "Unnecessary SMB access enabled",
      ],

      knownCves: [
        "CVE-2020-0796",
      ],

      openPorts: [445, 3389],

      isCriticalService: false,
      businessService: "Backup Service",
    },
  ],

  edges: [
    {
      id: "e1",
      source: "internet",
      target: "web-server",
      active: false,
    },
    {
      id: "e2",
      source: "web-server",
      target: "app-server",
      active: false,
    },
    {
      id: "e3",
      source: "app-server",
      target: "database",
      active: false,
    },
    {
      id: "e4",
      source: "database",
      target: "backup",
      active: false,
    },
  ],

  logs: [
    {
      id: "log-1",
      timestamp: new Date().toLocaleTimeString(),
      message: "Project Chronos dashboard initialised.",
      type: "system",
    },
  ],

  remediations: [
    {
      id: "r1",
      title: "Patch Apache HTTP Server",
      priority: "critical",

      affectedNodeId: "web-server",
      affectedNodeLabel: "Web Server",

      cve: "CVE-2021-41773",
      exploitFrequency: 78,
      riskReduction: 24,
    },

    {
      id: "r2",
      title: "Rotate application service credentials",
      priority: "high",

      affectedNodeId: "app-server",
      affectedNodeLabel: "Application Server",

      exploitFrequency: 54,
      riskReduction: 16,
    },

    {
      id: "r3",
      title: "Disable unnecessary SMB access",
      priority: "medium",

      affectedNodeId: "backup",
      affectedNodeLabel: "Backup Server",

      cve: "CVE-2020-0796",
      exploitFrequency: 31,
      riskReduction: 9,
    },
  ],
};