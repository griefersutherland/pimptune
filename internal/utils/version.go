package utils

var pimptuneVersion = "dev"

func GetPimptuneName() string {
	return "pimptune/v" + pimptuneVersion
}

func GetPimptuneVersion() string {
	return pimptuneVersion
}
