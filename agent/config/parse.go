// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/amazon-ecs-agent/agent/dockerclient"
	"github.com/aws/amazon-ecs-agent/agent/utils"

	"github.com/cihub/seelog"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/docker/go-connections/nat"
)

const (
	// envSkipDomainJoinCheck is an environment setting that can be used to skip
	// domain join check validation. This is useful for integration and
	// functional-tests but should not be set for any non-test use-case.
	envSkipDomainJoinCheck = "ZZZ_SKIP_DOMAIN_JOIN_CHECK_NOT_SUPPORTED_IN_PRODUCTION"
	// envSkipDomainLessCheck is an environment setting that can be used to skip
	// domain less gMSA support check validation. This is useful for integration and
	// functional-tests but should not be set for any non-test use-case.
	envSkipDomainLessCheck = "ZZZ_SKIP_DOMAIN_LESS_CHECK_NOT_SUPPORTED_IN_PRODUCTION"
	// envGmsaEcsSupport is an environment setting that can be used to enable gMSA support on ECS
	envGmsaEcsSupport = "ECS_GMSA_SUPPORTED"
	// envCredentialsFetcherHostDir is an environment setting that is set in ecs-init identifying
	// location of the credentials-fetcher location on the machine
	envCredentialsFetcherHostDir = "CREDENTIALS_FETCHER_HOST_DIR"
)

func parseCheckpoint(dataDir string) BooleanDefaultFalse {
	checkPoint := parseBooleanDefaultFalseConfig("ECS_CHECKPOINT")
	if dataDir != "" {
		// if we have a directory to checkpoint to, default it to be on
		if checkPoint.Value == NotSet {
			checkPoint.Value = ExplicitlyEnabled
		}
	}
	return checkPoint
}

func parseReservedPorts(env string) []uint16 {
	// Format: json array, e.g. [1,2,3]
	reservedPortEnv := os.Getenv(env)
	portDecoder := json.NewDecoder(strings.NewReader(reservedPortEnv))
	var reservedPorts []uint16
	err := portDecoder.Decode(&reservedPorts)
	// EOF means the string was blank as opposed to UnexepctedEof which means an
	// invalid parse
	// Blank is not a warning; we have sane defaults
	if err != io.EOF && err != nil {
		err := fmt.Errorf("Invalid format for \"%s\" environment variable; expected a JSON array like [1,2,3]. err %v", env, err)
		seelog.Warn(err)
	}

	return reservedPorts
}

func parseDockerStopTimeout() time.Duration {
	var dockerStopTimeout time.Duration
	parsedStopTimeout := parseEnvVariableDuration("ECS_CONTAINER_STOP_TIMEOUT")
	if parsedStopTimeout >= minimumDockerStopTimeout {
		dockerStopTimeout = parsedStopTimeout
		// if the ECS_CONTAINER_STOP_TIMEOUT is invalid or empty, then the parsedStopTimeout
		// will be 0, in this case we should return a 0,
		// because the DockerStopTimeout will merge with the DefaultDockerStopTimeout,
		// only when the DockerStopTimeout is empty
	} else if parsedStopTimeout != 0 {
		// if the configured ECS_CONTAINER_STOP_TIMEOUT is smaller than minimumDockerStopTimeout,
		// DockerStopTimeout will be set to minimumDockerStopTimeout
		// if the ECS_CONTAINER_STOP_TIMEOUT is 0, empty or an invalid value, then DockerStopTimeout
		// will be set to defaultDockerStopTimeout during the config merge operation
		dockerStopTimeout = minimumDockerStopTimeout
		seelog.Warnf("Discarded invalid value for docker stop timeout, parsed as: %v", parsedStopTimeout)
	}
	return dockerStopTimeout
}

func parseManifestPullTimeout() time.Duration {
	var timeout time.Duration
	parsedTimeout := parseEnvVariableDuration("ECS_MANIFEST_PULL_TIMEOUT")
	if parsedTimeout >= minimumManifestPullTimeout {
		timeout = parsedTimeout
	} else if parsedTimeout != 0 {
		// Parsed timeout too low
		timeout = minimumManifestPullTimeout
		seelog.Warnf("Discarded invalid value for manifest pull timeout, parsed as: %v", parsedTimeout)
	}
	return timeout
}

func parseContainerStartTimeout() time.Duration {
	var containerStartTimeout time.Duration
	parsedStartTimeout := parseEnvVariableDuration("ECS_CONTAINER_START_TIMEOUT")
	if parsedStartTimeout >= minimumContainerStartTimeout {
		containerStartTimeout = parsedStartTimeout
		// do the parsedStartTimeout != 0 check for the same reason as in getDockerStopTimeout()
	} else if parsedStartTimeout != 0 {
		containerStartTimeout = minimumContainerStartTimeout
		seelog.Warnf("Discarded invalid value for container start timeout, parsed as: %v", parsedStartTimeout)
	}
	return containerStartTimeout
}

func parseContainerCreateTimeout() time.Duration {
	var containerCreateTimeout time.Duration
	parsedCreateTimeout := parseEnvVariableDuration("ECS_CONTAINER_CREATE_TIMEOUT")
	if parsedCreateTimeout >= minimumContainerCreateTimeout {
		containerCreateTimeout = parsedCreateTimeout
		// do the parsedCreateTimeout != 0 check for the same reason as in getDockerStopTimeout()
	} else if parsedCreateTimeout != 0 {
		containerCreateTimeout = minimumContainerCreateTimeout
		seelog.Warnf("Discarded invalid value for container create timeout, parsed as: %v", parsedCreateTimeout)
	}
	return containerCreateTimeout
}

func parseImagePullInactivityTimeout() time.Duration {
	var imagePullInactivityTimeout time.Duration
	parsedImagePullInactivityTimeout := parseEnvVariableDuration("ECS_IMAGE_PULL_INACTIVITY_TIMEOUT")
	if parsedImagePullInactivityTimeout >= minimumImagePullInactivityTimeout {
		imagePullInactivityTimeout = parsedImagePullInactivityTimeout
		// do the parsedStartTimeout != 0 check for the same reason as in getDockerStopTimeout()
	} else if parsedImagePullInactivityTimeout != 0 {
		imagePullInactivityTimeout = minimumImagePullInactivityTimeout
		seelog.Warnf("Discarded invalid value for image pull inactivity timeout, parsed as: %v", parsedImagePullInactivityTimeout)
	}
	return imagePullInactivityTimeout
}

func parseAvailableLoggingDrivers() []dockerclient.LoggingDriver {
	availableLoggingDriversEnv := os.Getenv("ECS_AVAILABLE_LOGGING_DRIVERS")
	loggingDriverDecoder := json.NewDecoder(strings.NewReader(availableLoggingDriversEnv))
	var availableLoggingDrivers []dockerclient.LoggingDriver
	err := loggingDriverDecoder.Decode(&availableLoggingDrivers)
	// EOF means the string was blank as opposed to UnexpectedEof which means an
	// invalid parse
	// Blank is not a warning; we have sane defaults
	if err != io.EOF && err != nil {
		err := fmt.Errorf("Invalid format for \"ECS_AVAILABLE_LOGGING_DRIVERS\" environment variable; expected a JSON array like [\"json-file\",\"syslog\"]. err %v", err)
		seelog.Warn(err)
	}

	return availableLoggingDrivers
}

func parseVolumePluginCapabilities() []string {
	capsFromEnv := os.Getenv("ECS_VOLUME_PLUGIN_CAPABILITIES")
	if capsFromEnv == "" {
		return []string{}
	}
	capsDecoder := json.NewDecoder(strings.NewReader(capsFromEnv))
	var caps []string
	err := capsDecoder.Decode(&caps)
	if err != nil {
		seelog.Warnf("Invalid format for \"ECS_VOLUME_PLUGIN_CAPABILITIES\", expected a json list of string. error: %v", err)
	}
	return caps
}

func parseNumImagesToDeletePerCycle() int {
	numImagesToDeletePerCycleEnvVal := os.Getenv("ECS_NUM_IMAGES_DELETE_PER_CYCLE")
	numImagesToDeletePerCycle, err := strconv.Atoi(numImagesToDeletePerCycleEnvVal)
	if numImagesToDeletePerCycleEnvVal != "" && err != nil {
		seelog.Warnf("Invalid format for \"ECS_NUM_IMAGES_DELETE_PER_CYCLE\", expected an integer. err %v", err)
	}

	return numImagesToDeletePerCycle
}

func parseNumNonECSContainersToDeletePerCycle() int {
	numNonEcsContainersToDeletePerCycleEnvVal := os.Getenv("NONECS_NUM_CONTAINERS_DELETE_PER_CYCLE")
	numNonEcsContainersToDeletePerCycle, err := strconv.Atoi(numNonEcsContainersToDeletePerCycleEnvVal)
	if numNonEcsContainersToDeletePerCycleEnvVal != "" && err != nil {
		seelog.Warnf("Invalid format for \"NONECS_NUM_CONTAINERS_DELETE_PER_CYCLE\", expected an integer. err %v", err)
	}
	return numNonEcsContainersToDeletePerCycle
}

func parseImagePullBehavior() ImagePullBehaviorType {
	ImagePullBehaviorString := os.Getenv("ECS_IMAGE_PULL_BEHAVIOR")
	switch ImagePullBehaviorString {
	case "always":
		return ImagePullAlwaysBehavior
	case "once":
		return ImagePullOnceBehavior
	case "prefer-cached":
		return ImagePullPreferCachedBehavior
	default:
		// Use the default image pull behavior when ECS_IMAGE_PULL_BEHAVIOR is
		// "default" or not valid
		return ImagePullDefaultBehavior
	}
}

func parseInstanceAttributes(errs []error) (map[string]string, []error) {
	var instanceAttributes map[string]string
	instanceAttributesEnv := os.Getenv("ECS_INSTANCE_ATTRIBUTES")
	err := json.Unmarshal([]byte(instanceAttributesEnv), &instanceAttributes)
	if instanceAttributesEnv != "" {
		if err != nil {
			wrappedErr := fmt.Errorf("Invalid format for ECS_INSTANCE_ATTRIBUTES. Expected a json hash: %v", err)
			seelog.Error(wrappedErr)
			errs = append(errs, wrappedErr)
		}
	}
	for attributeKey, attributeValue := range instanceAttributes {
		seelog.Debugf("Setting instance attribute %v: %v", attributeKey, attributeValue)
	}

	return instanceAttributes, errs
}

func parseAdditionalLocalRoutes(errs []error) ([]cniTypes.IPNet, []error) {
	var additionalLocalRoutes []cniTypes.IPNet
	additionalLocalRoutesEnv := os.Getenv("ECS_AWSVPC_ADDITIONAL_LOCAL_ROUTES")
	if additionalLocalRoutesEnv != "" {
		err := json.Unmarshal([]byte(additionalLocalRoutesEnv), &additionalLocalRoutes)
		if err != nil {
			seelog.Errorf("Invalid format for ECS_AWSVPC_ADDITIONAL_LOCAL_ROUTES, expected a json array of CIDRs: %v", err)
			errs = append(errs, err)
		}
	}

	return additionalLocalRoutes, errs
}

func parseBooleanDefaultFalseConfig(envVarName string) BooleanDefaultFalse {
	boolDefaultFalseConfig := BooleanDefaultFalse{Value: NotSet}
	configString := strings.TrimSpace(os.Getenv(envVarName))
	if configString == "" {
		// if intentionally not set, do not add warning log
		return boolDefaultFalseConfig
	}

	res, err := strconv.ParseBool(configString)
	if err == nil {
		if res {
			boolDefaultFalseConfig.Value = ExplicitlyEnabled
		} else {
			boolDefaultFalseConfig.Value = ExplicitlyDisabled
		}
	} else {
		seelog.Warnf("Invalid format for \"%s\", expected a boolean. err %v", envVarName, err)
	}
	return boolDefaultFalseConfig
}

func parseBooleanDefaultTrueConfig(envVarName string) BooleanDefaultTrue {
	boolDefaultTrueConfig := BooleanDefaultTrue{Value: NotSet}
	configString := strings.TrimSpace(os.Getenv(envVarName))
	if configString == "" {
		// if intentionally not set, do not add warning log
		return boolDefaultTrueConfig
	}

	res, err := strconv.ParseBool(configString)
	if err == nil {
		if res {
			boolDefaultTrueConfig.Value = ExplicitlyEnabled
		} else {
			boolDefaultTrueConfig.Value = ExplicitlyDisabled
		}
	} else {
		seelog.Warnf("Invalid format for \"%s\", expected a boolean. err %v", envVarName, err)
	}
	return boolDefaultTrueConfig
}

func parseTaskMetadataThrottles() (int, int) {
	var steadyStateRate, burstRate int
	rpsLimitEnvVal := os.Getenv("ECS_TASK_METADATA_RPS_LIMIT")
	if rpsLimitEnvVal == "" {
		seelog.Debug("Environment variable empty: ECS_TASK_METADATA_RPS_LIMIT")
		return 0, 0
	}
	rpsLimitSplits := strings.Split(rpsLimitEnvVal, ",")
	if len(rpsLimitSplits) != 2 {
		seelog.Warn(`Invalid format for "ECS_TASK_METADATA_RPS_LIMIT", expected: "rateLimit,burst"`)
		return 0, 0
	}
	steadyStateRate, err := strconv.Atoi(strings.TrimSpace(rpsLimitSplits[0]))
	if err != nil {
		seelog.Warnf(`Invalid format for "ECS_TASK_METADATA_RPS_LIMIT", expected integer for steady state rate: %v`, err)
		return 0, 0
	}
	burstRate, err = strconv.Atoi(strings.TrimSpace(rpsLimitSplits[1]))
	if err != nil {
		seelog.Warnf(`Invalid format for "ECS_TASK_METADATA_RPS_LIMIT", expected integer for burst rate: %v`, err)
		return 0, 0
	}
	return steadyStateRate, burstRate
}

func parseContainerInstanceTags(errs []error) (map[string]string, []error) {
	var containerInstanceTags map[string]string
	containerInstanceTagsConfigString := os.Getenv("ECS_CONTAINER_INSTANCE_TAGS")

	// If duplicate keys exist, the value of the key will be the value of latter key.
	err := json.Unmarshal([]byte(containerInstanceTagsConfigString), &containerInstanceTags)
	if containerInstanceTagsConfigString != "" {
		if err != nil {
			wrappedErr := fmt.Errorf("Invalid format for ECS_CONTAINER_INSTANCE_TAGS. Expected a json hash: %v", err)
			seelog.Error(wrappedErr)
			errs = append(errs, wrappedErr)
		}
	}

	for tagKey, tagValue := range containerInstanceTags {
		seelog.Debugf("Setting instance tag %v: %v", tagKey, tagValue)
	}

	return containerInstanceTags, errs
}

func parseContainerInstancePropagateTagsFrom() ContainerInstancePropagateTagsFromType {
	containerInstancePropagateTagsFromString := os.Getenv("ECS_CONTAINER_INSTANCE_PROPAGATE_TAGS_FROM")
	switch containerInstancePropagateTagsFromString {
	case "ec2_instance":
		return ContainerInstancePropagateTagsFromEC2InstanceType
	default:
		// Use the default "none" type when ECS_CONTAINER_INSTANCE_PROPAGATE_TAGS_FROM is
		// "none" or not valid.
		return ContainerInstancePropagateTagsFromNoneType
	}
}

func parseEnvVariableUint16(envVar string) uint16 {
	envVal := os.Getenv(envVar)
	var var16 uint16
	if envVal != "" {
		var64, err := strconv.ParseUint(envVal, 10, 16)
		if err != nil {
			seelog.Warnf("Invalid format for \""+envVar+"\" environment variable; expected unsigned integer. err %v", err)
		} else {
			var16 = uint16(var64)
		}
	}
	return var16
}

func parseEnvVariableDuration(envVar string) time.Duration {
	var duration time.Duration
	envVal := os.Getenv(envVar)
	if envVal == "" {
		seelog.Debugf("Environment variable empty: %v", envVar)
	} else {
		var err error
		duration, err = time.ParseDuration(envVal)
		if err != nil {
			seelog.Warnf("Could not parse duration value: %v for Environment Variable %v : %v", envVal, envVar, err)
		}
	}
	return duration
}

func parseImageCleanupExclusionList(envVar string) []string {
	imageEnv := os.Getenv(envVar)
	var imageCleanupExclusionList []string
	if imageEnv == "" {
		seelog.Debugf("Environment variable empty: %s", imageEnv)
		return nil
	} else {
		imageCleanupExclusionList = strings.Split(imageEnv, ",")
	}

	return imageCleanupExclusionList
}

func parseCgroupCPUPeriod() time.Duration {
	duration := parseEnvVariableDuration("ECS_CGROUP_CPU_PERIOD")

	if duration >= minimumCgroupCPUPeriod && duration <= maximumCgroupCPUPeriod {
		return duration
	} else if duration != 0 {
		seelog.Warnf("CPU Period duration value: %v for Environment Variable ECS_CGROUP_CPU_PERIOD is not within [%v, %v], using default value instead",
			duration, minimumCgroupCPUPeriod, maximumCgroupCPUPeriod)
	}

	return defaultCgroupCPUPeriod
}

var getDynamicHostPortRange = utils.GetDynamicHostPortRange

func parseDynamicHostPortRange(dynamicHostPortRangeEnv string) string {
	dynamicHostPortRange := os.Getenv(dynamicHostPortRangeEnv)
	if dynamicHostPortRange != "" {
		_, _, err := nat.ParsePortRangeToInt(dynamicHostPortRange)
		if err != nil {
			seelog.Warnf("Invalid dynamicHostPortRange value from config: %s, err: %v", dynamicHostPortRange, err)
			return getDefaultDynamicHostPortRange()
		}
	} else {
		return getDefaultDynamicHostPortRange()
	}
	return dynamicHostPortRange
}

func getDefaultDynamicHostPortRange() string {
	startHostPortRange, endHostPortRange, err := getDynamicHostPortRange()
	if err != nil {
		seelog.Warnf("Unable to read the ephemeral host port range, "+
			"falling back to the default range: %v-%v", utils.DefaultPortRangeStart, utils.DefaultPortRangeEnd)
		return fmt.Sprintf("%d-%d", utils.DefaultPortRangeStart, utils.DefaultPortRangeEnd)
	}
	return fmt.Sprintf("%d-%d", startHostPortRange, endHostPortRange)
}
