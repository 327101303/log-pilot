package pilot

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/yaml"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Global variables for FilebeatPiloter
const (
	FILEBEAT_EXEC_CMD  = "/usr/bin/filebeat"
	FILEBEAT_REGISTRY  = "/var/lib/filebeat/registry"
	FILEBEAT_BASE_CONF = "/etc/filebeat"
	FILEBEAT_CONF_DIR  = FILEBEAT_BASE_CONF + "/prospectors.d"
	FILEBEAT_CONF_FILE = FILEBEAT_BASE_CONF + "/filebeat.yml"

	DOCKER_SYSTEM_PATH  = "/var/lib/docker/"
	KUBELET_SYSTEM_PATH = "/var/lib/kubelet/"

	ENV_FILEBEAT_OUTPUT = "FILEBEAT_OUTPUT"
)

var filebeat *exec.Cmd
var _ Piloter = (*FilebeatPiloter)(nil)

// FilebeatPiloter for filebeat plugin
type FilebeatPiloter struct {
	name           string
	baseDir        string
	watchDone      chan bool
	watchDuration  time.Duration
	watchContainer map[string]string
}

// NewFilebeatPiloter returns a FilebeatPiloter instance
// 初始化一个piloter对象，参数为/host
func NewFilebeatPiloter(baseDir string) (Piloter, error) {
	return &FilebeatPiloter{
		name:           PILOT_FILEBEAT,
		baseDir:        baseDir,
		watchDone:      make(chan bool),
		watchContainer: make(map[string]string, 0),
		watchDuration:  60 * time.Second,
	}, nil
}

var configOpts = []ucfg.Option{
	ucfg.PathSep("."),
	// PathSep设置路径分隔符，该分隔符用于将名称拆分成类似树的层次结构。
	//如果未设置PathSep，则不会拆分字段名称。
	ucfg.ResolveEnv,
	// ResolveEnv选项在可用项中添加一个查找回调以查找值
	// OS环境变量。
	ucfg.VarExp,
	// VarExp选项启用对变量扩展的支持。 只有设置了VarExp，Resolve和Env选项才有效。
}

// Config contains all log paths
type Config struct {
	Paths []string `config:"paths"`
}

// FileInode identify a unique log file
type FileInode struct {
	Inode  uint64 `json:"inode,"`
	Device uint64 `json:"device,"`
}

// RegistryState represents log offsets
type RegistryState struct {
	Source      string        `json:"source"`
	Offset      int64         `json:"offset"`
	Timestamp   time.Time     `json:"timestamp"`
	TTL         time.Duration `json:"ttl"`
	Type        string        `json:"type"`
	FileStateOS FileInode
}

func (p *FilebeatPiloter) watch() error {
	log.Infof("%s watcher start", p.Name())  //INFO[0000] filebeat watcher start
	for {
		select {
		case <-p.watchDone: //监听watchDone的channel，如果可以执行就退出
			log.Infof("%s watcher stop", p.Name())
			return nil
		case <-time.After(p.watchDuration)://隔执行时长循环一次，减少
			//log.Debugf("%s watcher scan", p.Name())
			err := p.scan() //执行scan方法
			if err != nil {
				log.Errorf("%s watcher scan error: %v", p.Name(), err)
			}
		}
	}
}



//获取注册文件
// 获取filebeat配置文件
// 判断filebeat中指定的配置文件是否能删除
func (p *FilebeatPiloter) scan() error {
	// 当piloter容器重启时，重新获取已经存在filebeat注册文件
	states, err := p.getRegsitryState() //读取/var/lib/filebeat/,返回statesmap:map[collect sour]filebeat_registry
	if err != nil {
		return nil
	}
	//
	configPaths := p.loadConfigPaths()  //configpaths=filebeat配置文件中采集的路径 map[/etc/filebeat/prospectors.d]{containerid...}
	for container := range p.watchContainer {  // 遍历watchcontainer这个map
		confPath := p.GetConfPath(container) //返回filebeta采集该容器日志的配置文件具体路径
		if _, err := os.Stat(confPath); err != nil && os.IsNotExist(err) { //如果不存在这个filebeta配置文件
			log.Infof("log config %s.yml has been removed and ignore", container)
			delete(p.watchContainer, container)//删除watchcontainer这个map中的对应container值
		} else if p.canRemoveConf(container, states, configPaths) { // 如果配置文件存在，判断是否可以删除filebeat配置
			log.Infof("try to remove log config %s.yml", container)   //try to remove log config c1f0c84cf87d73d407f8d6c6561e4ba16e42f8b1097e6a674e31681f9f96b9f3.yml
			if err := os.Remove(confPath); err != nil { //如果删除配置文件成功
				log.Errorf("remove log config %s.yml fail: %v", container, err)
			} else {
				delete(p.watchContainer, container)//从watchContainer的map中删除该kv
			}
		}
	}
	return nil
}



// 判断filebeat对应的配置文件是否可以删除
// 可以删除：1、路径不在filebeat注册文件中，可能文件已删除 2、已经采集完毕
// 不能删除：1、未采集完毕 2、filebeat中不存在这个配置文件
func (p *FilebeatPiloter) canRemoveConf(container string, registry map[string]RegistryState,
	configPaths map[string]string) bool {
	config, err := p.loadConfig(container) //传入容器id，返回filebeat配置文件路径
	if err != nil {
		return false
	}

	for _, path := range config.Paths {  //遍历filebeat中采集路径paths切片
		// filepath.Dir(path)取采集路径的目录
		autoMount := p.isAutoMountPath(filepath.Dir(path)) // 那采集路径的目录和dockervolume、kubeletvolume匹配，判断是哪种
		logFiles, _ := filepath.Glob(path) //返回匹配到到到文件切片
		for _, logFile := range logFiles {//遍历文件名切片
			info, err := os.Stat(logFile) //判断是否存在
			if err != nil && os.IsNotExist(err) {//不存在，跳过
				continue
			}
			if _, ok := registry[logFile]; !ok {//判断是否在filebeat的注册文件中
				log.Warnf("%s->%s registry not exist", container, logFile)
				continue
			}
			if registry[logFile].Offset < info.Size() {//对比filebeta注册文件中到offset和文件的总大小，判断是否采集完毕
				if autoMount { // ephemeral logs //日志未采集完毕，临时的日志，返回false跳过删除日志
					log.Infof("%s->%s does not finish to read", container, logFile)
					return false
				} else if _, ok := configPaths[path]; !ok { // host path bind//filebeat配置文件没有这个采集路径
					log.Infof("%s->%s does not finish to read and not exist in other config",
						container, logFile)
					return false
				}
			}
		}
	}
	return true
}


// 把containerid传给loadconfig
func (p *FilebeatPiloter) loadConfig(container string) (*Config, error) {
	confPath := p.GetConfPath(container)//  返回一个配置文件存储路径/etc/filebeat/prospectors.d/"containerID".yml
	//把filebeat某个配置文件和解析配置文件的struct传入
	/*type Config struct {
		ctx      context
		metadata *Meta
		fields   *fields
	}
	 */
	c, err := yaml.NewConfigWithFile(confPath, configOpts...)  //
	if err != nil {
		log.Errorf("read %s.yml log config error: %v", container, err)
		return nil, err
	}

	var config Config //filebeat配置文件中的paths
	if err := c.Unpack(&config); err != nil {// 把struct解压为config指针，里面存放了配置文件中的paths，就是采集路径
		log.Errorf("parse %s.yml log config error: %v", container, err)
		return nil, err
	}
	return &config, nil
}

func (p *FilebeatPiloter) loadConfigPaths() map[string]string {
	paths := make(map[string]string, 0)
	confs, _ := ioutil.ReadDir(p.GetConfHome()) // /etc/filebeat/prospectors.d 返回文件名切片
	for _, conf := range confs {
		container := strings.TrimRight(conf.Name(), ".yml") //删除文件名中指定的后缀
		if _, ok := p.watchContainer[container]; ok {
			continue // ignore removed container
		}

		config, err := p.loadConfig(container)// 获取filebeat配置文件对应的配置文件
		if err != nil || config == nil {
			continue
		}

		for _, path := range config.Paths { //配置文件绝对路径
			if _, ok := paths[path]; !ok {
				paths[path] = container //生成一个切片map[/etc/filebeat/prospectors.d]{containerid}
			}
		}
	}
	return paths
}

func (p *FilebeatPiloter) isAutoMountPath(path string) bool {
	dockerVolumePattern := fmt.Sprintf("^%s.*$", filepath.Join(p.baseDir, DOCKER_SYSTEM_PATH))
	if ok, _ := regexp.MatchString(dockerVolumePattern, path); ok {
		return true
	}

	kubeletVolumePattern := fmt.Sprintf("^%s.*$", filepath.Join(p.baseDir, KUBELET_SYSTEM_PATH))
	ok, _ := regexp.MatchString(kubeletVolumePattern, path)
	return ok
}


// 获取filebeat注册状态
func (p *FilebeatPiloter) getRegsitryState() (map[string]RegistryState, error) {
	f, err := os.Open(FILEBEAT_REGISTRY) //打开filebeat注册文件/var/lib/filebeat/regsitry
	if err != nil {
		return nil, err
	}
	defer f.Close()

	decoder := json.NewDecoder(f) //解析filbeat采集状态的json文件
	states := make([]RegistryState, 0) //初始化一个切片：RegistryState
	err = decoder.Decode(&states) //把json文件解析到map-decoder中
	if err != nil {
		return nil, err
	}

	statesMap := make(map[string]RegistryState, 0)  //初始化一个statesmap【string】RegistryState
	for _, state := range states { //遍历filebeat注册文件切片
		if _, ok := statesMap[state.Source]; !ok { // 如果filebeat注册文件中某一条source不再statemap中
			statesMap[state.Source] = state  // 设置statemap的key=采集路径，value=filebeat注册文件中对应的一条json
		}
	}//循环filebeat注册文件，如果采集的注册文件不再statemap中添加进去，应该是依靠statesmap生成filebeat的配置文件
	return statesMap, nil
}

func (p *FilebeatPiloter) feed(containerID string) error {
	if _, ok := p.watchContainer[containerID]; !ok {
		p.watchContainer[containerID] = containerID
		log.Infof("begin to watch log config: %s.yml", containerID)
	}
	return nil
}

// Start starting and watching filebeat process
// 启动filebat
func (p *FilebeatPiloter) Start() error {
	// 如果filebeat变量不为空
	if filebeat != nil {
		pid := filebeat.Process.Pid //获取filebat的pid
		log.Infof("filebeat started, pid: %v", pid) //INFO[0000] filebeat started: 17
		return fmt.Errorf(ERR_ALREADY_STARTED) //返回已经启动
	}

	log.Info("starting filebeat") //启动
	filebeat = exec.Command(FILEBEAT_EXEC_CMD, "-c", FILEBEAT_CONF_FILE) //封装filebeat的启动命令
	filebeat.Stderr = os.Stderr //把filebeat本身的日志设置为终端
	filebeat.Stdout = os.Stdout
	err := filebeat.Start() //exec.Command.Start方法启动filebeat
	if err != nil {
		log.Errorf("filebeat start fail: %v", err) //启动失败，错误信息
	}

	go func() {
		log.Infof("filebeat started: %v", filebeat.Process.Pid) //INFO[0000] filebeat started: 17
		//等待命令退出并等待任何复制到 stdin或从stdout或stderr复制以完成。
		//
		//命令必须已由Start启动。
		//
		//如果命令运行，返回的错误为零，没有问题		//复制STDIN、STDUT和STDRR，并以零出口退出 //状态。
		//
		//如果命令无法运行或未能成功完成，则 错误是类型* ExitError。其他错误类型可能是//因I/O问题返回。
		//
		//如果c.Stdin、c.Stdout或c.Stderr中的任何一个不是*os.File，那么Wait也将等待
		//为各自的I/O循环复制到或从该进程复制到完成。
		//
		//Wait释放与Cmd关联的任何资源。
		err := filebeat.Wait()  //exec.command.Wait方法
		if err != nil {
			log.Errorf("filebeat exited: %v", err)
			if exitError, ok := err.(*exec.ExitError); ok {
				processState := exitError.ProcessState
				log.Errorf("filebeat exited pid: %v", processState.Pid())
			}
		}

		// try to restart filebeat
		log.Warningf("filebeat exited and try to restart")
		// 设置filebeat变量为空
		filebeat = nil
		// 重新调用start方法启动filebeat//如果错误一直重启
		p.Start()
	}()
	//新启动一个goroutine执行watch方法
	go p.watch()
	return err
}

// Stop log collection
func (p *FilebeatPiloter) Stop() error {
	p.watchDone <- true
	return nil
}

// Reload reload configuration file
func (p *FilebeatPiloter) Reload() error {
	log.Debug("do not need to reload filebeat")
	return nil
}

// GetConfPath returns log configuration path
func (p *FilebeatPiloter) GetConfPath(container string) string {
	// /etc/filebeat/prospectors.d/c1f0c84cf87d73d407f8d6c6561e4ba16e42f8b1097e6a674e31681f9f96b9f3.yml
	return fmt.Sprintf("%s/%s.yml", FILEBEAT_CONF_DIR, container)
}

// GetConfHome returns configuration directory
func (p *FilebeatPiloter) GetConfHome() string {
	return FILEBEAT_CONF_DIR
}

// Name returns plugin name
func (p *FilebeatPiloter) Name() string {
	return p.name
}

// OnDestroyEvent watching destroy event
func (p *FilebeatPiloter) OnDestroyEvent(container string) error {
	return p.feed(container)
}

// GetBaseConf returns plugin root directory
func (p *FilebeatPiloter) GetBaseConf() string {
	return FILEBEAT_BASE_CONF
}
