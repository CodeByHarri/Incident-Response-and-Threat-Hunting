# Analyzing Google Analytics Data 

# Description
This query extracts and decodes Google Analytics data from URLs to provide detailed insights into user activity, helping digital forensics and incident response teams understand user behavior, session information, and various metadata. The query parses URL components, extracts __utma cookie information, and decodes URL-encoded strings, projecting them into a structured format.

# Sentinel / Defender
```kql
yourwebproxylog
| where TimeGenerated >ago(30d) // Filter data to only include records from the last 30 days
| where URL_s contains "google-analytics" // Filter records where the URL contains "google-analytics"
| extend utma = tostring(split(tostring(split(URL_s, '&_utma=')[1]),'&_')[0]) // Extract the value of the "_utma" parameter from the URL
| extend URLComponents = parse_url(URL_s) // Parse the URL into its components
| extend URLParams = URLComponents["Query Parameters"], // Extract the query parameters from the URL
          Host = URLComponents["Host"], // Extract the host part of the URL
          Scheme = URLComponents["Scheme"], // Extract the scheme part of the URL (e.g., "http", "https")
          Path = URLComponents["Path"] // Extract the path part of the URL
| extend DecodedDocumentTitle = replace_string(tostring(URLParams["dt"]), "%20", " ") // Decode the document title by replacing "%20" with spaces
| extend DomainHash = tostring(split(utma,'.')[0]) // Extract the domain hash from the "_utma" value
| project
    Referer_s, // Project the Referer column
    Path, // Project the Path column
    SourceUser_s, // Project the SourceUser column
    Host, // Project the Host column
    DomainHash, // Project the DomainHash column
    UniqueVisitorID = tostring(split(utma,'.')[1]), // Extract and project the unique visitor ID from the "_utma" value
    FirstVisitTimestamp = unixtime_seconds_todatetime(tolong(split(utma,'.')[2])), // Convert and project the first visit timestamp from the "_utma" value
    PreviousVisitTimestamp = unixtime_seconds_todatetime(tolong(split(utma,'.')[3])), // Convert and project the previous visit timestamp from the "_utma" value
    CurrentVisitTimestamp = unixtime_seconds_todatetime(tolong(split(utma,'.')[4])), // Convert and project the current visit timestamp from the "_utma" value
    Version = Scheme["v"], // Project the version from the scheme 
    TrackingID = Scheme["tid"], // Project the tracking ID from the scheme 
    GoogleTagManagerID = Scheme["gtm"], // Project the Google Tag Manager ID from the scheme 
    ApplicationID = Scheme["_p"], // Project the application ID from the scheme
    GoogleConversionData = Scheme["gcd"], // Project the Google conversion data from the scheme 
    NoPersonalization = Scheme["npa"], // Project the no personalization flag from the scheme 
    DesignatedMarketArea = Scheme["dma"], // Project the designated market area from the scheme 
    TagExperimentInfo = Scheme["tag_exp"], // Project the tag experiment information from the scheme 
    ClientID = Scheme["cid"], // Project the client ID from the scheme 
    UserLanguage = Scheme["ul"], // Project the user language from the scheme 
    ScreenResolution = Scheme["sr"], // Project the screen resolution from the scheme 
    UserAgentArchitecture = Scheme["uaa"], // Project the user agent architecture from the scheme 
    UserAgentBitness = Scheme["uab"], // Project the user agent bitness from the scheme 
    UserAgentFullVersionList = Scheme["uafvl"], // Project the user agent full version list from the scheme 
    UserAgentMobile = Scheme["uamb"], // Project the user agent mobile flag from the scheme 
    UserAgentModel = Scheme["uam"], // Project the user agent model from the scheme 
    UserAgentPlatform = Scheme["uap"], // Project the user agent platform from the scheme 
    UserAgentPlatformVersion = Scheme["uapv"], // Project the user agent platform version from the scheme 
    UserAgentWidth = Scheme["uaw"], // Project the user agent width from the scheme 
    AdReportingEnabled = Scheme["are"], // Project the ad reporting enabled flag from the scheme 
    FlashRenderingMode = Scheme["frm"], // Project the flash rendering mode from the scheme 
    PreScribeComponentLoader = Scheme["pscdl"], // Project the PreScribe component loader from the scheme 
    EnhancedUserAgent = Scheme["_eu"], // Project the enhanced user agent from the scheme 
    SessionNumber = Scheme["_s"], // Project the session number from the scheme 
    SessionID = Scheme["sid"], // Project the session ID from the scheme 
    SessionCount = Scheme["sct"], // Project the session count from the scheme 
    SessionEngagement = Scheme["seg"], // Project the session engagement from the scheme 
    DocumentLocationURL = Scheme["dl"], // Project the document location URL from the scheme 
    VisitCount = tolong(split(utma,'.')[5]), // Extract and project the visit count from the "_utma" value
    Version_u = URLParams["v"], // Project the version from the URL parameters
    ProtocolVersion = URLParams["_v"], // Project the protocol version from the URL parameters
    ApplicationID_u  = URLParams["a"], // Project the application ID from the URL parameters
    HitType = URLParams["t"], // Project the hit type from the URL parameters
    SessionNumber_u  = URLParams["_s"], // Project the session number from the URL parameters
    DocumentLocationURL_u  = URLParams["dl"], // Project the document location URL from the URL parameters
    UserLanguage_u  = URLParams["ul"], // Project the user language from the URL parameters
    DocumentEncoding = URLParams["de"], // Project the document encoding from the URL parameters
    DocumentTitle = DecodedDocumentTitle, // Project the decoded document title
    ScreenColors = URLParams["sd"], // Project the screen colors from the URL parameters
    ScreenResolution_u  = URLParams["sr"], // Project the screen resolution from the URL parameters
    ViewportSize = URLParams["vp"], // Project the viewport size from the URL parameters
    JavaEnabled = URLParams["je"], // Project the Java enabled flag from the URL parameters
    CampaignTracking = URLParams["_utmz"], // Project the campaign tracking information from the URL parameters
    HitTimestamp =  unixtime_seconds_todatetime(tolong(URLParams["_utmht"])), // Project the hit timestamp from the URL parameters
    ClientID_u  = URLParams["cid"], // Project the client ID from the URL parameters
    TrackingID_u  = URLParams["tid"], // Project the tracking ID from the URL parameters
    AnotherIdentifier = URLParams["_gid"], // Project another identifier from the URL parameters
    GoogleTagManagerID_u  = URLParams["gtm"], // Project the Google Tag Manager ID from the URL parameters
    GoogleConversionData_u  = URLParams["gcd"], // Project the Google conversion data from the URL parameters
    DesignatedMarketArea_u  = URLParams["dma"], // Project the designated market area from the URL parameters
    TagExperimentInfo_u = URLParams["tag_exp"], // Project the tag experiment information from the URL parameters
    JavaScriptCut = URLParams["jsscut"], // Project the JavaScript cut information from the URL parameters
    CacheBuster = URLParams["z"] // Project the cache buster value from the URL parameters
```
