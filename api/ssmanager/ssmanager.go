package ssmanager

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/yuant2021/XrayR/api"
)

type APIClient struct {
	client           *resty.Client
	APIHost          string
	NodeID           int
	Key              string
	NodeType         string
	EnableVless      bool
	EnableXTLS       bool
	SpeedLimit       float64
	DeviceLimit      int
	LocalRuleList    []api.DetectRule
	ConfigResp       *simplejson.Json
	LastReportOnline map[int]int
	access           sync.Mutex
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {

	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	client.SetQueryParam("token", apiConfig.Key)
	nodeID := strconv.Itoa(apiConfig.NodeID)
	client.SetQueryParam("node_id", nodeID)
	// client.SetDebug(true)
	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"node_id": strconv.Itoa(apiConfig.NodeID),
		"token":   apiConfig.Key,
	})
	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		EnableXTLS:    apiConfig.EnableXTLS,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
	}
	return apiClient
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {

	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		//handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return make([]api.DetectRule, 0)
		}

		file.Close()
	}

	return LocalRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %s", c.assembleURL(path), string(body), err)
	}
	rtn, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("Ret %s invalid", res.String())
	}
	return rtn, nil
}

// GetNodeInfo will pull NodeInfo Config from SSManager
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	path := ""

	res, err := c.client.R().
		SetQueryParam("action", "node_info").
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	c.access.Lock()
	defer c.access.Unlock()
	c.ConfigResp = response
	if err != nil {
		return nil, err
	}

	nodeInfo, err = c.parseSSManagerNodeResponse(response)

	if err != nil {
		res, _ := response.MarshalJSON()
		return nil, fmt.Errorf("Parse node info failed: %s, \nError: %s", string(res), err)
	}

	return nodeInfo, nil
}

// ParseSSNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) parseSSManagerNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	nodeinfo := &api.NodeInfo{}
	switch nodeInfoResponse.Get("node_type").MustString() {
	case "1":
		port, _ := strconv.Atoi(nodeInfoResponse.Get("node_sport").MustString())
		method := nodeInfoResponse.Get("node_config").Get("E").MustString()
		c.NodeType = "Shadowsocks"
		nodeinfo = &api.NodeInfo{
			NodeType:          "Shadowsocks",
			NodeID:            c.NodeID,
			Port:              port,
			TransportProtocol: "tcp",
			CypherMethod:      method,
		}
		//TODO
	}

	// Create GeneralNodeInfo
	// nodeinfo := &api.NodeInfo{
	// 	NodeType:          c.NodeType,
	// 	NodeID:            c.NodeID,
	// 	Port:              port,
	// 	TransportProtocol: "tcp",
	// 	CypherMethod:      method,
	// }

	return nodeinfo, nil
}

func (c *APIClient) GetNodeRule() (*[]api.DetectRule, *[]string, error) {
	ruleList := c.LocalRuleList
	var protocolRule []string
	path := ""
	res, err := c.client.R().
		SetQueryParam("action", "get_audit").
		ForceContentType("application/json").
		Get(path)
	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, nil, err
	}
	c.access.Lock()
	defer c.access.Unlock()
	numRules := len(response.MustArray())
	if numRules > 0 {
		for i := 0; i < numRules; i++ {
			if response.GetIndex(i).Get("type").MustString() == "1" {
				rule_id, _ := strconv.Atoi(response.GetIndex(i).Get("id").MustString())
				ruleListItem := api.DetectRule{
					ID:      rule_id,
					Pattern: regexp.MustCompile(response.GetIndex(i).Get("regex").MustString()),
				}
				ruleList = append(ruleList, ruleListItem)
			} else {
				if response.GetIndex(i).Get("type").MustString() == "2" {
					protocolRule = append(protocolRule, response.GetIndex(i).Get("regex").MustString())
				}
			}
		}
	}
	// fmt.Println(ruleList)
	return &ruleList, &protocolRule, nil
}

// ReportNodeStatus implements the API interface
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	path := ""
	systemload := SystemLoad{
		Uptime: strconv.Itoa(nodeStatus.Uptime),
		Load:   fmt.Sprintf("%.2f %.2f %.2f", nodeStatus.CPU/100, nodeStatus.CPU/100, nodeStatus.CPU/100),
	}

	res, err := c.client.R().
		SetBody(systemload).
		SetQueryParam("action", "report_node_status").
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

//ReportNodeOnlineUsers implements the API interface
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	data := make([]OnlineUser, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = OnlineUser{UID: user.UID, IP: user.IP}
		if _, ok := reportOnline[user.UID]; ok {
			reportOnline[user.UID]++
		} else {
			reportOnline[user.UID] = 1
		}
	}
	c.LastReportOnline = reportOnline // Update LastReportOnline

	path := ""
	res, err := c.client.R().
		SetQueryParam("action", "report_node_online").
		SetBody(data).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportIllegal implements the API interface
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	data := make([]IllegalItem, len(*detectResultList))
	for i, r := range *detectResultList {
		data[i] = IllegalItem{
			ID:  r.RuleID,
			UID: r.UID,
		}
	}
	path := ""
	res, err := c.client.R().
		SetQueryParam("action", "report_audit").
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	return nil
}

func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	path := ""
	res, err := c.client.R().
		SetQueryParam("action", "get_user").
		ForceContentType("application/json").
		Get(path)
	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	numOfUsers := len(response.MustArray())
	userList := make([]api.UserInfo, numOfUsers)
	for i := 0; i < numOfUsers; i++ {
		user := api.UserInfo{}
		user.UID, _ = strconv.Atoi(response.GetIndex(i).Get("id").MustString())
		speedlimit, _ := strconv.Atoi(response.GetIndex(i).Get("port_speed_limit").MustString())
		if speedlimit == 0 {
			user.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		} else {
			user.SpeedLimit = uint64(speedlimit * 1000000 / 8)
		}
		connectorlimit, _ := strconv.Atoi(response.GetIndex(i).Get("connector_limit").MustString())
		if connectorlimit == 0 {
			user.DeviceLimit = c.DeviceLimit
		} else {
			user.DeviceLimit = connectorlimit
		}
		switch c.NodeType {
		case "Shadowsocks":
			user.Email = response.GetIndex(i).Get("email").MustString()
			user.Passwd = response.GetIndex(i).Get("uuid").MustString()
			// case "Trojan":
			// 	user.UUID = response.Get("data").GetIndex(i).Get("trojan_user").Get("password").MustString()
			// 	user.Email = response.Get("data").GetIndex(i).Get("trojan_user").Get("password").MustString()
			// case "V2ray":
			// 	user.UUID = response.Get("data").GetIndex(i).Get("v2ray_user").Get("uuid").MustString()
			// 	user.Email = response.Get("data").GetIndex(i).Get("v2ray_user").Get("email").MustString()
			// 	user.AlterID = response.Get("data").GetIndex(i).Get("v2ray_user").Get("alter_id").MustInt()
			//TODO
		}
		userList[i] = user
		// fmt.Println(user)
	}
	return &userList, nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	path := ""
	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download}
	}
	res, err := c.client.R().
		SetQueryParam("action", "report_flow").
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	return nil
}
