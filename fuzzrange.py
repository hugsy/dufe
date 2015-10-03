import mutators


class FuzzRange:

    def __init__(self, range, mutators):
        self.start, self.end = FuzzRange.parse_range_from_string(range)
        self.mutators = FuzzRange.parse_mutator_from_string(mutators)
        self.keep_original_size = False
        return


    def __str__(self):
        return  "FuzzRange[%d,%d](len=%d) -> %s" % (self.start,
                                                    self.end,
                                                    self.size,
                                                    ",".join([x.__name__+'()' for x in self.mutators]))


    @property
    def size(self):
        return self.end - self.start + 1


    def get_next_value(self, orig_value):
        for mutator in self.mutators:
            for fuzz in mutator(orig_value, self.keep_original_size ):
                yield( fuzz  )
        return


    @staticmethod
    def parse_range_from_string(s):
        r = s.split("-")
        try:
            start = int(r[0])
            end = int(r[1])
            if end < start:
                return ()

        except IndexError:
            return (start, start)

        except TypeError:
            return (-1, -1)

        return (start, end)


    @staticmethod
    def parse_mutator_from_string(s):
        mut = []
        for m in s.replace(" ", "").split("|"):
            try:
                mut.append( getattr(mutators, s) )
            except AttributeError:
                continue
        return mut
