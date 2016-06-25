# AM_CXXFLAGS = -I../../ $(BOOST_CPPFLAGS)
# AM_LDFLAGS = $(BOOST_LDFLAGS)

bin_PROGRAMS = winEVTViewer
winEVTViewer_SOURCES = winEVTViewer.cpp
winEVTViewer_CXXFLAGS = $(POPT_CFLAGS) -I../../
winEVTViewer_LDADD = $(POPT_LIBS) ../../libtimeUtils/src/libtimeUtils.a ../../libWinEVT/src/libWinEVT.a ../../libpasswdFile/src/libpasswdFile.a ../../libbinData/src/libbinData.a ../../libdelimText/src/libdelimText.a

