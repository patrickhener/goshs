package integration

const (
	// Content of test data to test for view and download
	test_data string = `Men wanted for hazardous journey.
Low wages, bitter cold, long hours of complete darkness.
Safe return doubtful.
Honour and recognition in event of success`

	// note that per docs, each testcontainer uses a random port to avoid collisions
	// we fetch that port at test runtime
	UnsecuredServerPort = 8001
	UnsecuredWebdavPort = 8002
	UnsecuredSMBPort    = 8445
)
