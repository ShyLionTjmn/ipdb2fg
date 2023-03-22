package main

import (
  "log"
  "fmt"
  "flag"
  "time"
  "os"
  "regexp"
  "encoding/json"
  "database/sql"
  "net/http"
  "net/url"
  "crypto/tls"
  "io"
  "strings"
  "strconv"
  "bytes"
  _ "github.com/go-sql-driver/mysql"
  . "github.com/ShyLionTjmn/m"
  . "github.com/ShyLionTjmn/dbtools"
)

const DEFAULT_CONFIG_FILE = "/etc/ipdb/ipdb.config"

type FG struct {
  Name string `json:"name"`
  Addr string `json:"addr"`
}

type Config struct {
  Db_dsn string `json:"DSN"`
  Autofg_tag string `json:"autofg_tag"`
  Rest_user string `json:"rest_user"`
  Rest_key string `json:"rest_key"`
  Fortigates []FG `json:"fortigates"`
}

func V4ip2long(str string) (uint32, bool) {
  parts := strings.Split(str,".")
  if len(parts) != 4 { return 0, false }
  o1, err := strconv.ParseUint(parts[0], 10, 8)
  if err != nil { return 0, false }
  o2, err := strconv.ParseUint(parts[1], 10, 8)
  if err != nil { return 0, false }
  o3, err := strconv.ParseUint(parts[2], 10, 8)
  if err != nil { return 0, false }
  o4, err := strconv.ParseUint(parts[3], 10, 8)
  if err != nil { return 0, false }

  return uint32(o1) << 24 | uint32(o2) << 16 | uint32(o3) << 8 | uint32(o4), true
}

func main() {
  _ = fmt.Sprint()
  var err error
  var opt_C string
  var opt_y bool

  good_hostname := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_\-\.]*[a-zA-Z0-9]$`)
  bad_hostname := regexp.MustCompile(`^(?i:reserve|dhcp.*pool|dhcp.*start|dhcp.*end|dhcp.*beg|dhcp.*stop)`)
  ipdb_comment := regexp.MustCompile(`(?i:\Wipdb\W)`)
  lock_comment := regexp.MustCompile(`(?i:\Wlock\W)`)

  var config Config

  flag.StringVar(&opt_C, "C", DEFAULT_CONFIG_FILE, "Config file location")
  flag.BoolVar(&opt_y, "y", false, "Really make changes")
  flag.Parse()

  var conf_json []byte
  if conf_json, err = os.ReadFile(opt_C); err != nil { log.Fatal(err.Error()) }

  if err = json.Unmarshal(conf_json, &config); err != nil { log.Fatal(err.Error()) }

  var rows []M
  var db *sql.DB
  var query string

  if db, err = sql.Open("mysql", config.Db_dsn); err != nil { log.Fatal(err.Error()) }
  defer db.Close()

  query = "SELECT tag_id FROM tags WHERE tag_api_name=?"
  if rows, err = Return_query_A(db, query, config.Autofg_tag); err != nil { log.Fatal(err.Error()) }

  if len(rows) != 1 { log.Fatal("No \"" + config.Autofg_tag + "\" tag in DB\n") }

  var tag_id string
  var var_ok bool

  if tag_id, var_ok = rows[0].Vse("tag_id"); !var_ok { log.Fatal("Cannot get tag_id\n") }

  reg := "(^|,)" + tag_id + "(,|$)";

  query = "SELECT v4net_addr as first, v4net_last as last FROM v4nets" +
          " WHERE v4net_tags REGEXP(?)"
  var ranges []M
  if ranges, err = Return_query_A(db, query, reg); err != nil { panic(err) }

  query = "SELECT INET_NTOA(v4ip_addr) AS ip, iv_value AS hostname FROM ((v4nets" +
          " INNER JOIN v4ips ON v4ip_fk_v4net_id = v4net_id)" +
          " INNER JOIN i4vs ON iv_fk_v4ip_id = v4ip_id)" +
          " INNER JOIN ics ON iv_fk_ic_id = ic_id" +
          " WHERE v4net_tags REGEXP(?)" +
          " AND ic_api_name='hostname'"

  var db_ips M
  if db_ips, err = Return_query_M(db, query, "ip", reg); err != nil { panic(err) }

  for ip, _ := range db_ips {
    hostname := db_ips.Vs(ip, "hostname")

    if good_hostname.MatchString(hostname) && !bad_hostname.MatchString(hostname) {
      db_ips.VM(ip)["db_name"] = ip + " * " + hostname
    }
    //fmt.Println(ip, db_ips.Vs(ip, "hostname"))
  }

/*
      {
      "name":"10.96.37.57 - blitz",
      "q_origin_key":"10.96.37.57 - blitz",
      "uuid":"2761e89e-c324-51ed-7e2e-a42541c23009",
      "subnet":"10.96.37.57 255.255.255.255",
      "type":"ipmask",
      "sub-type":"sdn",
      "clearpass-spt":"unknown",
      "start-mac":"00:00:00:00:00:00",
      "end-mac":"00:00:00:00:00:00",
      "country":"",
      "cache-ttl":0,
      "sdn":"",
      "fsso-group":[
      ],
      "interface":"",
      "obj-type":"ip",
      "comment":"",
      "associated-interface":"",
      "color":0,
      "filter":"",
      "sdn-addr-type":"private",
      "obj-id":"",
      "list":[
      ],
      "tagging":[
      ],
      "allow-routing":"disable",
      "fabric-object":"disable"
    },
*/

  // POST ../ - create 
  // PUT  ../"name" - modify
  // GET  ../ - get

  for _, fg := range config.Fortigates {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{
      Timeout: 5*time.Second,
      Transport: tr,
    }
    req_url := "https://" + fg.Addr + "/api/v2/cmdb/firewall/address/?access_token=" + config.Rest_key +
           "&format=name|comment|subnet" +
           //"&filter=type=@ipmask" +
           "&filter=subnet=@%20255.255.255.255" +
           ""
    req, err := http.NewRequest("GET", req_url, nil)
    if err != nil { panic(err) }
    req.Header.Add("Content-type", "application/json")

    var resp *http.Response
    if resp, err = client.Do(req); err != nil { panic(err) }

    var resp_json []byte
    if resp_json, err = io.ReadAll(resp.Body); err != nil { panic(err) }

    var fg_addresses M
    if err = json.Unmarshal(resp_json, &fg_addresses); err != nil { panic(err) }

    fg_ips := M{}

    fg_names := M{}

    for _, fg_addr_i := range fg_addresses.VA("results").([]interface{}) {
      fg_addr := fg_addr_i.(M)
      if strings.HasSuffix(fg_addr.Vs("subnet"), " 255.255.255.255") {
        ip := strings.TrimSuffix(fg_addr.Vs("subnet"), " 255.255.255.255")
        fg_ips[ip] = M{
          "fg_name": fg_addr.Vs("name"),
          "comment": fg_addr.Vs("comment"),
        }

        fg_names[fg_addr.Vs("name")] = fg_addr
      }
    }

    rename_queue := []M{}
    add_queue := []M{}

    for ip, _ := range fg_ips {
      ipu, var_ok := V4ip2long(ip)
      if !var_ok  { panic("bad ip: "+ip) }
      if db_ips[ip] == nil {
        in_range := false
        for _, r := range ranges {
          if uint64(ipu) >= r.Vu("first") && uint64(ipu) <= r.Vu("last") {
            in_range = true
            break
          }
        }
        if in_range &&
           !lock_comment.MatchString(fg_ips.Vs(ip, "comment")) &&
           !strings.HasPrefix(fg_ips.Vs(ip, "fg_name"), "!") &&
        true {
          new_name := "!" + fg_ips.Vs(ip, "fg_name")

          if fg_names[new_name] == nil {
            rename_queue = append(rename_queue, M{
              "old_name": fg_ips.Vs(ip, "fg_name"),
              "new_name": new_name,
              "ip": ip,
            })
          } else {
            fmt.Fprintln(os.Stderr, fg.Name, ": Rename conflict: ", ip)
          }
        }
      } else {
        if !lock_comment.MatchString(fg_ips.Vs(ip, "comment")) &&
        db_ips.Evs(ip, "db_name") &&
        (fg_ips.Vs(ip, "fg_name") != db_ips.Vs(ip, "db_name") ||
         strings.Index(fg_ips.Vs(ip, "comment"), STRING_ERROR) >= 0) &&
        true {
          new_name := db_ips.Vs(ip, "db_name")

          if fg_names[new_name] == nil {
            rename_queue = append(rename_queue, M{
              "old_name": fg_ips.Vs(ip, "fg_name"),
              "new_name": new_name,
              "old_comment": fg_ips.Vs(ip, "comment"),
              "ip": ip,
            })
          } else {
            fmt.Fprintln(os.Stderr, fg.Name, ": Rename conflict: ", ip)
          }
        }
      }
    }

    for ip, _ := range db_ips {
      if fg_ips[ip] == nil && db_ips.Evs(ip, "db_name") {
        new_name := db_ips.Vs(ip, "db_name")
        if fg_names[new_name] == nil {
          add_queue = append(add_queue, M{
            "new_name": new_name,
            "ip": ip,
          })
        } else {
          fmt.Fprintln(os.Stderr, fg.Name, ": Add name conflict: ", ip)
        }
      }
    }

    for _, entry := range rename_queue {
      req_url := "https://" + fg.Addr + "/api/v2/cmdb/firewall/address/" +
             url.PathEscape(entry.Vs("old_name")) +
             "?access_token=" + config.Rest_key +
             ""

      comment := entry.Vs("old_comment")
      if !ipdb_comment.MatchString(comment) {
        if comment == "" {
          comment = "ipdb"
        } else {
          comment += ", ipdb"
        }
      }

      send_data := M{
        "name": entry.Vs("new_name"),
        "comment": comment,
      }

      var send_bytes []byte
      if send_bytes, err = json.Marshal(send_data); err != nil { panic(err) }

      req, err := http.NewRequest("PUT", req_url, bytes.NewReader(send_bytes))
      if err != nil { panic(err) }
      req.Header.Add("Content-type", "application/json")

      fmt.Println(fg.Name, ": rename: ", entry.Vs("old_name"), " to: ", entry.Vs("new_name"))

      if !opt_y { continue }

      var resp *http.Response
      if resp, err = client.Do(req); err != nil { panic(err) }

      var resp_json []byte
      if resp_json, err = io.ReadAll(resp.Body); err != nil { panic(err) }

      var fg_resp M
      if err = json.Unmarshal(resp_json, &fg_resp); err != nil { panic(err) }

      if fg_resp.Vs("status") != "success" {
        fmt.Fprintln(os.Stderr, fg.Name, ": query: " + string(send_bytes))
        fmt.Fprintln(os.Stderr, fg.Name, ": PUT ERROR: " + string(resp_json))
      }
    }

    for _, entry := range add_queue {
      req_url := "https://" + fg.Addr + "/api/v2/cmdb/firewall/address/" +
             "?access_token=" + config.Rest_key +
             ""
      send_data := M{
        "name": entry.Vs("new_name"),
        "comment": "ipdb",
        "subnet": entry.Vs("ip") + " 255.255.255.255",
        "type": "ipmask",
        "sub-type": "sdn",
        "sdn-addr-type": "private",
        "obj-type": "ip",
        "interface": "",
      }

      var send_bytes []byte
      if send_bytes, err = json.Marshal(send_data); err != nil { panic(err) }

      req, err := http.NewRequest("POST", req_url, bytes.NewReader(send_bytes))
      if err != nil { panic(err) }
      req.Header.Add("Content-type", "application/json")

      fmt.Println(fg.Name, ": add: ", entry.Vs("new_name"))

      if !opt_y { continue }

      var resp *http.Response
      if resp, err = client.Do(req); err != nil { panic(err) }

      var resp_json []byte
      if resp_json, err = io.ReadAll(resp.Body); err != nil { panic(err) }

      var fg_resp M
      if err = json.Unmarshal(resp_json, &fg_resp); err != nil { panic(err) }

      if fg_resp.Vs("status") != "success" {
        fmt.Fprintln(os.Stderr, fg.Name, ": query: " + string(send_bytes))
        fmt.Fprintln(os.Stderr, fg.Name, ": POST ERROR: " + string(resp_json))
      }
    }
  }
}
