AM_CXXFLAGS = -I../../../ $(BOOST_CPPFLAGS)
AM_LDFLAGS = $(BOOST_LDFLAGS) $(BOOST_DATE_TIME_LIB) $(POPT_LIBS)

bin_PROGRAMS = winEVTViewer
winEVTViewer_SOURCES = winEVTViewer.cpp
winEVTViewer_LDADD = ../../libtimeUtils/src/libtimeUtils.a ../../libWinEVT/src/libWinEVT.a ../../libpasswdFile/src/libpasswdFile.a ../../libbinData/src/libbinData.a ../../libdelimText/src/libdelimText.a

