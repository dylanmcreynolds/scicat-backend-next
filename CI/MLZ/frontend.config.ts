export default {
  lbBaseURL: "https://scicat-dev.k8s-test.frm2.tum.de",
  archiveWorkflowEnabled: true,
  retrieveDestinations: [
    {
      option: "MLZ",
      location: "/home/out"
    },
    {
      option: "MLZ S3 (Testphase)"
    }
  ],
  accessTokenPrefix: "Bearer ",
  lbTokenPrefix: "Bearer ",
  externalAuthEndpoint: "",
  editMetadataEnabled: true,
  editSampleEnabled: true,
  editPublishedData: true,
  scienceSearchEnabled: true,
  facility: "MLZ",
  multipleDownloadEnabled: true,
  shoppingCartEnabled: true,
  shoppingCartOnHeader: true,
  ingestManual: "https://forge.frm2.tum.de/wiki/services:scicat",
  gettingStarted: "https://forge.frm2.tum.de/wiki/services:scicat",
  jupyterHubUrl: "http://172.25.72.238:8009/hub/login",
  riotBaseUrl: "",
  datasetReduceEnabled: true,
  fileColorEnabled: true,
  jsonMetadataEnabled: true,
  localColumns: [
    {
      name: "select",
      order: 0,
      type: "standard",
      enabled: true
    },
    {
      name: "datasetName",
      order: 1,
      type: "standard",
      enabled: true
    },
    {
      name: "runNumber",
      order: 2,
      type: "standard",
      enabled: true
    },
    {
      name: "sourceFolder",
      order: 3,
      type: "standard",
      enabled: true
    },
    {
      name: "size",
      order: 4,
      type: "standard",
      enabled: true
    },
    {
      name: "creationTime",
      order: 5,
      type: "standard",
      enabled: true
    },
    {
      name: "type",
      order: 6,
      type: "standard",
      enabled: true
    },
    {
      name: "image",
      order: 7,
      type: "standard",
      enabled: true
    },
    {
      name: "metadata",
      order: 8,
      type: "standard",
      enabled: true
    },
    {
      name: "proposalId",
      order: 9,
      type: "standard",
      enabled: true
    },
    {
      name: "ownerGroup",
      order: 10,
      type: "standard",
      enabled: true
    },
    {
      name: "dataStatus",
      order: 11,
      type: "standard",
      enabled: true
    }
  ],
  logbookEnabled: true,
  metadataPreviewEnabled: true,
  maxDirectDownloadSize: 5000000000,
  multipleDownloadAction: "http://localhost:3011/zip",
  searchSamples: true,
  sftpHost: "",
  tableSciDataEnabled: true,
  shareEnabled: false,
  searchPublicDataEnabled: true,
  landingPage: "",
  fileDownloadEnabled: false,
  jobsEnabled: true,
  policiesEnabled: true,
  addDatasetEnabled: true,
  editDatasetSampleEnabled: true,
  scienceSearchUnitsEnabled: true,
  metadataStructure: "",
  loginFormEnabled: true,
  oAuth2Endpoints: [
	  {
		  displayText: "MLZ",
		  authURL: "api/v3/auth/oidc"}
  ]
};
